package config

// expandMacrosWithFunctions expands every macro reference in value: $(NAME),
// $(NAME:default) and the special functions ($ENV, $INT, $SUBSTR, $F...).
// See expand.go.
func (c *Config) expandMacrosWithFunctions(value string) (string, error) {
	return c.expandMacro(value)
}

// evaluateFunctionMacro evaluates one special macro function, given without
// its leading '$' (e.g. "ENV(HOME)").
func (c *Config) evaluateFunctionMacro(funcCall string) (string, error) {
	return c.expandMacro("$" + funcCall)
}
