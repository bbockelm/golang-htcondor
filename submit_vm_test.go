// The VM universe attributes. Every expectation here is also pinned against
// HTCondor's own SubmitHash by a seed in fuzz/submit/differential_test.go.
// That comparison runs in a job of its own, which builds libcondor_utils from
// source and only on changes that touch the parser; this file runs in the
// ordinary test job on every change and needs no HTCondor. The one case the
// oracle cannot pin is marked where it appears.
package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// vmAd builds the job ad for one VM submit file.
func vmAd(t *testing.T, submit string) *classad.ClassAd {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	return ad
}

func vmWantInt(t *testing.T, ad *classad.ClassAd, attr string, want int64) {
	t.Helper()
	got, ok := ad.EvaluateAttrInt(attr)
	if !ok || got != want {
		t.Errorf("%s = %d (ok=%v), want %d", attr, got, ok, want)
	}
}

func vmWantString(t *testing.T, ad *classad.ClassAd, attr, want string) {
	t.Helper()
	got, ok := ad.EvaluateAttrString(attr)
	if !ok || got != want {
		t.Errorf("%s = %q (ok=%v), want %q", attr, got, ok, want)
	}
}

func vmWantBool(t *testing.T, ad *classad.ClassAd, attr string, want bool) {
	t.Helper()
	got, ok := ad.EvaluateAttrBool(attr)
	if !ok || got != want {
		t.Errorf("%s = %v (ok=%v), want %v", attr, got, ok, want)
	}
}

func vmWantAbsent(t *testing.T, ad *classad.ClassAd, attr string) {
	t.Helper()
	if e, ok := ad.Lookup(attr); ok {
		t.Errorf("%s = %s, want it unset", attr, e)
	}
}

const vmKVMPrelude = "universe = vm\nvm_type = kvm\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\n"

// The VM keywords land under HTCondor's attribute names, not the keywords'
// own. Writing VM_Memory or VM_VCPUs instead leaves an ad nothing reads, so
// the VM boots with the vmgahp's default memory and CPU count.
func TestVMAttributeNames(t *testing.T) {
	ad := vmAd(t, vmKVMPrelude+"vm_vcpus = 4\nvm_macaddr = 00:11:22:33:44:55\nqueue\n")

	vmWantString(t, ad, "JobVMType", "kvm")
	vmWantInt(t, ad, "JobVMMemory", 512)
	vmWantInt(t, ad, "JobVM_VCPUS", 4)
	vmWantString(t, ad, "JobVM_MACADDR", "00:11:22:33:44:55")
	vmWantString(t, ad, "VMPARAM_vm_Disk", "d.img:vda:w")

	// The keyword-named attributes are gone for good.
	for _, attr := range []string{"VM_Type", "VM_Memory", "VM_VCPUs", "VM_MACAddr", "VM_Disk"} {
		vmWantAbsent(t, ad, attr)
	}
}

// vm_type is stored lower-cased, and it is what decides whether the disk and
// the xen_* keywords are read at all.
func TestVMTypeIsLowerCased(t *testing.T) {
	ad := vmAd(t, "universe = vm\nvm_type = KVM\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nqueue\n")
	vmWantString(t, ad, "JobVMType", "kvm")
	vmWantString(t, ad, "VMPARAM_vm_Disk", "d.img:vda:w")
}

// Checkpoint, networking and the VNC console are in the ad whether or not the
// submit file mentions them; the networking type is read only when networking
// is on.
func TestVMBooleanDefaults(t *testing.T) {
	ad := vmAd(t, vmKVMPrelude+"vm_networking_type = bridge\nqueue\n")
	vmWantBool(t, ad, "JobVMCheckpoint", false)
	vmWantBool(t, ad, "JobVMNetworking", false)
	vmWantBool(t, ad, "JobVMVNCConsole", false)
	vmWantAbsent(t, ad, "JobVMNetworkingType")
	vmWantAbsent(t, ad, "VMPARAM_No_Output_VM")

	ad = vmAd(t, vmKVMPrelude+"vm_networking = true\nvm_networking_type = bridge\nvm_checkpoint = yes\nvm_vnc = 1\nvm_no_output_vm = true\nqueue\n")
	vmWantBool(t, ad, "JobVMCheckpoint", true)
	vmWantBool(t, ad, "JobVMNetworking", true)
	vmWantBool(t, ad, "JobVMVNCConsole", true)
	vmWantString(t, ad, "JobVMNetworkingType", "bridge")
	vmWantBool(t, ad, "VMPARAM_No_Output_VM", true)
}

// vm_vcpus is the leading integer of the value with a floor of 1, and it is
// always in the ad.
func TestVMVCPUs(t *testing.T) {
	for value, want := range map[string]int64{"4": 4, "0": 1, "-3": 1, "abc": 1, "2 cpus": 2, "4294967296": 1} {
		ad := vmAd(t, vmKVMPrelude+"vm_vcpus = "+value+"\nqueue\n")
		vmWantInt(t, ad, "JobVM_VCPUS", want)
	}
	vmWantInt(t, vmAd(t, vmKVMPrelude+"queue\n"), "JobVM_VCPUS", 1)
}

// vm_memory falls back to $(Request_Memory) and vm_vcpus to $(Request_CPUs),
// and the fallback is the macro's text rather than the evaluated request --
// request_cpus = 2*2 gives the VM two CPUs, not four.
func TestVMMemoryAndCPUsFallBackToTheRequest(t *testing.T) {
	ad := vmAd(t, "universe = vm\nvm_type = kvm\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nrequest_memory = 1024\nrequest_cpus = 2*2\nqueue\n")
	vmWantInt(t, ad, "JobVMMemory", 1024)
	vmWantInt(t, ad, "JobVM_VCPUS", 2)

	ad = vmAd(t, "universe = vm\nvm_type = kvm\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nRequestMemory = 777\nRequestCpus = 6\nqueue\n")
	vmWantInt(t, ad, "JobVMMemory", 777)
	vmWantInt(t, ad, "JobVM_VCPUS", 6)
}

// With no request_memory of its own, a VM job asks the pool for the memory
// its VM was given.
func TestVMRequestMemoryFollowsVMMemory(t *testing.T) {
	ad := vmAd(t, vmKVMPrelude+"queue\n")
	vmWantInt(t, ad, "RequestMemory", 512)
}

// The xen_* keywords become VMPARAM_Xen_* attributes, and only for a Xen VM:
// under any other vm_type condor_submit never reads them.
func TestXenParams(t *testing.T) {
	src := "vm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\n" +
		"xen_kernel = /boot/vmlinuz\nxen_root = /dev/sda1\nxen_initrd = /boot/initrd\nxen_kernel_params = \"ro quiet\"\nqueue\n"

	ad := vmAd(t, "universe = vm\nvm_type = xen\n"+src)
	vmWantString(t, ad, "VMPARAM_Xen_Kernel", "/boot/vmlinuz")
	vmWantString(t, ad, "VMPARAM_Xen_Root", "/dev/sda1")
	vmWantString(t, ad, "VMPARAM_Xen_Initrd", "/boot/initrd")
	// One layer of quoting comes off the kernel command line.
	vmWantString(t, ad, "VMPARAM_Xen_Kernel_Params", "ro quiet")
	vmWantAbsent(t, ad, "JobVMHardwareVT")
	for _, attr := range []string{"Xen_Kernel", "Xen_Root", "Xen_Initrd", "Xen_KernelParams"} {
		vmWantAbsent(t, ad, attr)
	}

	ad = vmAd(t, "universe = vm\nvm_type = kvm\n"+src)
	for _, attr := range []string{"VMPARAM_Xen_Kernel", "VMPARAM_Xen_Root", "VMPARAM_Xen_Initrd", "VMPARAM_Xen_Kernel_Params"} {
		vmWantAbsent(t, ad, attr)
	}
}

// "included" boots the kernel out of the disk image and "vmx" asks for
// hardware virtualization. Neither is a kernel file, so there is no root
// device to name and a xen_root written anyway is read by nobody; "vmx" turns
// on JobVMHardwareVT.
func TestXenKernelWithoutAKernelFile(t *testing.T) {
	tail := "vm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nxen_root = /dev/sda1\nqueue\n"

	ad := vmAd(t, "universe = vm\nvm_type = xen\nxen_kernel = included\n"+tail)
	vmWantString(t, ad, "VMPARAM_Xen_Kernel", "included")
	vmWantAbsent(t, ad, "VMPARAM_Xen_Root")
	vmWantAbsent(t, ad, "JobVMHardwareVT")

	ad = vmAd(t, "universe = vm\nvm_type = xen\nxen_kernel = vmx\n"+tail)
	vmWantString(t, ad, "VMPARAM_Xen_Kernel", "vmx")
	vmWantAbsent(t, ad, "VMPARAM_Xen_Root")
	vmWantBool(t, ad, "JobVMHardwareVT", true)
}

// The one case the oracle cannot pin, because the two sides disagree about
// accepting the file rather than about the ad: condor_submit rejects
// xen_initrd without a kernel file ("To use xen_initrd, xen_kernel should be
// a real kernel file"), where the Go parser accepts the file and drops the
// keyword. This asserts Go's own behavior, not parity.
func TestXenInitrdWithoutAKernelFileIsDropped(t *testing.T) {
	ad := vmAd(t, "universe = vm\nvm_type = xen\nxen_kernel = included\nvm_memory = 512\nvm_disk = d.img:vda:w\nexecutable = /bin/sleep\nxen_initrd = /boot/initrd\nqueue\n")
	vmWantString(t, ad, "VMPARAM_Xen_Kernel", "included")
	vmWantAbsent(t, ad, "VMPARAM_Xen_Initrd")
}
