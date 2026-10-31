package htcondor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// containerImageParam and dockerImageParam read the two image keywords
// the way SubmitHash does: submit_param(SUBMIT_KEY_ContainerImage,
// ATTR_CONTAINER_IMAGE), so the job attribute's own name is an accepted
// second spelling and a value that expands to nothing means the command
// was not given at all.
func (sf *SubmitFile) containerImageParam() (string, bool) {
	return sf.simpleKeywordParam("container_image", "ContainerImage")
}

func (sf *SubmitFile) dockerImageParam() (string, bool) {
	return sf.simpleKeywordParam("docker_image", "DockerImage")
}

// isContainerUniverse reports whether the submit file asked for
// `universe = container`. Like `universe = docker` it is a topping on
// the vanilla universe rather than a universe of its own, so by the time
// parseUniverse is done the spelling is the only record of it.
func (sf *SubmitFile) isContainerUniverse() bool {
	univ, ok := sf.submitCommand("universe")
	return ok && strings.EqualFold(strings.TrimSpace(univ), "container")
}

// containerJobRoles is SubmitHash::SetUniverse's IsDockerJob /
// IsContainerJob pair, which is what every other container decision is
// gated on.
//
// The two are not simply "what the universe line said". An image keyword
// in a vanilla or local job makes it an implicit CONTAINER job even
// though the universe line says nothing, which is how `container_image`
// works without `universe = container`. The docker universe is the one
// place that never becomes a container job, and it refuses a
// container_image outright.
//
// Outside vanilla and local -- grid, vm, java, scheduler -- neither flag
// is ever set, so an image keyword there is read by nobody. The Go
// parser used to write DockerImage and ContainerImage in any universe,
// which put an image on a grid job's ad that condor_submit leaves bare.
func (sf *SubmitFile) containerJobRoles() (isDocker, isContainer bool, err error) {
	isDocker = sf.isDockerUniverse()
	isContainer = sf.isContainerUniverse()

	if sf.universe != UniverseVanilla && sf.universe != UniverseLocal {
		return isDocker, isContainer, nil
	}

	_, hasContainerImg := sf.containerImageParam()
	if isDocker {
		if hasContainerImg {
			return false, false, fmt.Errorf("docker universe does not allow use of container_image")
		}
		return isDocker, isContainer, nil
	}

	_, hasDockerImg := sf.dockerImageParam()
	switch {
	case hasDockerImg && hasContainerImg:
		return false, false, fmt.Errorf("cannot declare both docker_image and container_image")
	case hasDockerImg || hasContainerImg:
		isContainer = true
	}
	return isDocker, isContainer, nil
}

// containerImageInvalidPrefixes are the schemes check_container_image
// refuses: HTCondor has no transfer plugin or runtime path for any of
// them, so a job naming one would be matched and then fail on the
// execute node.
var containerImageInvalidPrefixes = []string{"instance://", "library://", "shub://"}

// checkContainerImage is check_container_image: trim the value, drop one
// surrounding pair of quotes, and reject the schemes HTCondor cannot
// run. An image that is empty after that is rejected too.
func checkContainerImage(raw string) (string, bool) {
	image := trimAndStripSubmitQuotes(raw)
	for _, prefix := range containerImageInvalidPrefixes {
		if strings.HasPrefix(image, prefix) {
			return image, false
		}
	}
	return image, image != ""
}

// condorBasename is condor_basename: everything after the last '/'. It
// is deliberately not path.Base, which collapses "" and "/" to "." and
// "/" and strips a trailing separator -- the caller has already removed
// the one trailing separator HTCondor removes, and the rest of
// HTCondor's answer is this.
func condorBasename(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// isSubmitURL is IsUrl() from src/condor_utils/condor_url.cpp. HTCondor
// is stricter than RFC 3986: it insists on the "//" authority marker and
// on something after it, so "mailto:x" is not a URL here and
// "osdf:///a/b" is.
func isSubmitURL(s string) bool {
	isAlpha := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	i := 1
	for i < len(s) {
		c := s[i]
		if isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' {
			i++
			continue
		}
		break
	}
	return i+3 < len(s) && s[i] == ':' && s[i+1] == '/' && s[i+2] == '/'
}

// splitSubmitTokens is StringTokenIterator with STI_TRIM: the string is
// cut on any of delims, each token is trimmed, and empty tokens are
// dropped.
func splitSubmitTokens(s, delims string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(delims, r)
	}) {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// setContainerImages is the container half of SubmitHash::SetExecutable:
// it writes DockerImage and ContainerImage, and the want-flags that tell
// the starter which runtime to use, for a job that is a docker or
// container job and for no other.
//
// The image written here is not necessarily the one that reaches the
// job: processContainerInputFiles rewrites ContainerImage to the
// image's basename once it has decided to transfer it. That ordering is
// condor_submit's, and it is why setContainerSettings now runs before
// setFileTransfer.
func (sf *SubmitFile) setContainerImages(ad *classad.ClassAd, isDocker, isContainer bool) error {
	if isDocker {
		raw, ok := sf.dockerImageParam()
		if !ok {
			return fmt.Errorf("docker jobs require a docker_image")
		}
		image := trimAndStripSubmitQuotes(raw)
		if image == "" {
			return fmt.Errorf("'%s' is not a valid docker_image", raw)
		}
		_ = ad.Set("DockerImage", image)
		_ = ad.Set("WantDocker", true)
		return nil
	}
	if !isContainer {
		return nil
	}

	// container universe also allows docker_image, to force a docker
	// image to be used; it is the image kind rather than the runtime,
	// so the job is still a container job.
	raw, hasDocker := sf.dockerImageParam()
	if hasDocker {
		image := trimAndStripSubmitQuotes(raw)
		if image == "" {
			return fmt.Errorf("'%s' is not a valid docker_image for container universe", raw)
		}
		_ = ad.Set("DockerImage", image)
		_ = ad.Set("WantDockerImage", true)
	}

	if raw, ok := sf.containerImageParam(); ok {
		image, valid := checkContainerImage(raw)
		if !valid {
			return fmt.Errorf("'%s' is not a valid container image", raw)
		}
		_ = ad.Set("ContainerImage", image)
		// The image-kind flag is what actually turns the container
		// runtime on in the starter (WantContainer alone does not on
		// an Apptainer node). condor_submit sets exactly one of
		// these from the image type; mirror that.
		wantAttr, _ := containerImageKind(image)
		_ = ad.Set(wantAttr, true)
	} else if !hasDocker {
		return fmt.Errorf("container jobs require a container_image or docker_image")
	}
	_ = ad.Set("WantContainer", true)
	return nil
}

// setContainerServices is SubmitHash::SetContainerSpecial.
//
// Two things about it are easy to get wrong. It is gated on the job
// being a docker or container job, so `container_service_names` on a
// scheduler job reaches the ad in condor_submit not at all -- the Go
// parser wrote it for any universe. And every service named here MUST
// have a port: condor_submit refuses the submit file outright when one
// does not, because a service with no port is a service nothing can
// reach, and the name alone would have the startd publish an endpoint
// the job never listens on.
//
// The list itself is stored exactly as written rather than
// canonicalized; it is an f_as_string value in SubmitHash's hands.
func (sf *SubmitFile) setContainerServices(ad *classad.ClassAd, isDocker, isContainer bool) error {
	if !isDocker && !isContainer {
		return nil
	}
	services, ok := sf.simpleKeywordParam("container_service_names", "ContainerServiceNames")
	if !ok {
		return nil
	}
	_ = ad.Set("ContainerServiceNames", services)

	for _, service := range splitSubmitTokens(services, ", \t\r\n") {
		value, ok := sf.submitCommand(service + "_container_port")
		if ok && value != "" {
			port, valid := evalLongParam(value)
			if !valid {
				return fmt.Errorf("%s_container_port=%s is invalid, must eval to an integer", service, value)
			}
			if port >= 0 && port <= 65535 {
				_ = ad.Set(service+"_ContainerPort", port)
				continue
			}
		}
		return fmt.Errorf("requested container service %q was not assigned a port, or the assigned port was not valid", service)
	}
	return nil
}

// processContainerInputFiles is SubmitHash::process_container_input_files:
// the decision of where a container image comes from, and whether the
// file transfer has to carry it.
//
// It reports whether it added the image to inputFiles, which is
// SetTransferFiles' in_files_specified -- a container job whose image is
// transferred has an input list even when the submit file named no
// transfer_input_files.
//
// The attribute it writes last is the one that matters most. Once
// condor_submit decides to transfer the image, the name the starter must
// run is the name the transfer leaves in the sandbox, which is the
// image's BASENAME; the submit-side path moves to
// ContainerImageFullPath, where late materialization reads it to build
// each proc's own input list. Writing the submit-side path into
// ContainerImage instead -- which is what the Go parser did -- tells the
// starter to run a path the sandbox does not have.
func (sf *SubmitFile) processContainerInputFiles(ad *classad.ClassAd, inputFiles *[]string) (bool, error) {
	_, isContainer, err := sf.containerJobRoles()
	if err != nil {
		return false, err
	}
	if !isContainer {
		return false, nil
	}

	// transfer_container = false says the image is already on the
	// execute node, so there is nothing to carry and nothing to
	// rename. Read from the keyword rather than from the ad: the
	// custom-attribute pass that could also set TransferContainer runs
	// after this point in condor_submit too, so `+TransferContainer =
	// false` does NOT turn the transfer off there either.
	if value, ok := sf.simpleKeywordParam("transfer_container", "TransferContainer"); ok {
		if want, valid := evalBoolParam(value); valid && !want {
			_ = ad.Set("ContainerImageSource", "local")
			return false, nil
		}
	}

	image, ok := sf.containerImageParam()
	if !ok {
		// Only docker_image was given, which names a repository rather
		// than a file: there is nothing to transfer and no source to
		// record.
		return false, nil
	}

	// An image under a filesystem every execute node already mounts is
	// local wherever the job lands, so it is never transferred.
	shared, _ := sf.param("CONTAINER_SHARED_FS")
	for _, base := range splitSubmitTokens(shared, ",") {
		if strings.HasPrefix(image, base) {
			_ = ad.Set("ContainerImageSource", "local")
			return false, nil
		}
	}

	// A repository URL is pulled by the runtime on the execute node,
	// not fetched by the file transfer.
	for _, prefix := range []string{"docker://", "oras://"} {
		if strings.HasPrefix(image, prefix) {
			_ = ad.Set("ContainerImageSource", strings.TrimSuffix(prefix, "://"))
			return false, nil
		}
	}

	if sf.containerImageIsCommon(image) {
		sf.addCommonContainerCatalog(ad, image)
	} else {
		*inputFiles = append(*inputFiles, image)
	}

	// A sandbox image is a directory and may be written with a trailing
	// separator; one of those is removed so the basename is the
	// directory's name rather than nothing.
	trimmed := strings.TrimSuffix(image, "/")
	_ = ad.Set("ContainerImage", condorBasename(trimmed))
	_ = ad.Set("ContainerImageFullPath", image)
	if colon := strings.IndexByte(trimmed, ':'); colon < 0 {
		_ = ad.Set("ContainerImageSource", "cedar")
	} else {
		_ = ad.Set("ContainerImageSource", trimmed[:colon])
	}
	return true, nil
}

// containerImageIsCommon reports whether this image is a COMMON input
// file: one the execute node caches and reuses across jobs instead of
// receiving a copy per job. The job asks with container_is_common, and
// the pool can ask on every job's behalf with
// CONTAINER_IMAGES_COMMON_BY_DEFAULT or for a set of images with
// CONTAINER_REGEX_COMMON_BY_DEFAULT.
//
// An unusable regex is ignored rather than fatal, the way condor_submit
// ignores it: it is the administrator's typo, and failing every submit
// in the pool over it helps nobody.
func (sf *SubmitFile) containerImageIsCommon(image string) bool {
	common := false
	if v, ok := sf.param("CONTAINER_IMAGES_COMMON_BY_DEFAULT"); ok {
		if b, valid := evalBoolParam(strings.TrimSpace(v)); valid {
			common = b
		}
	}
	if expr, ok := sf.param("CONTAINER_REGEX_COMMON_BY_DEFAULT"); ok && strings.TrimSpace(expr) != "" {
		// std::regex_match wants the WHOLE string, which is Go's
		// default only for an anchored pattern.
		if re, err := regexp.Compile(`\A(?:` + expr + `)\z`); err == nil && re.MatchString(image) {
			common = true
		}
	}
	// The job's own answer outranks both knobs. condor_submit reads it
	// off the job ad, where the simple-keyword pass has already put it;
	// here that pass runs after this point, so read the keyword itself.
	if value, ok := sf.simpleKeywordParam("container_is_common", "ContainerIsCommon"); ok {
		if b, valid := evalBoolParam(value); valid {
			common = b
		}
	}
	return common
}

// addCommonContainerCatalog records a common image as an input CATALOG
// rather than as an input file: the execute node is told which cached
// image to use, and nothing is transferred.
//
// The catalog is named after a hash of the image's full path rather than
// after the image, because two DAG nodes in one pool may use different
// images with the same basename and a collision would give one of them
// the other's image.
func (sf *SubmitFile) addCommonContainerCatalog(ad *classad.ClassAd, image string) {
	hashKey := image
	if !isSubmitURL(image) {
		if iwd, err := sf.jobIwd(); err == nil {
			hashKey = fullPath(image, iwd)
		}
	}
	sum := sha256.Sum256([]byte(hashKey))
	catalog := "container_" + hex.EncodeToString(sum[:])[:8]
	_ = ad.Set("_x_catalog_"+catalog, image)

	existing, _ := ad.EvaluateAttrString("CommonInputCatalogs")
	if strings.Contains(existing, catalog) {
		return
	}
	if existing != "" {
		existing += ", "
	}
	_ = ad.Set("CommonInputCatalogs", existing+catalog)
}
