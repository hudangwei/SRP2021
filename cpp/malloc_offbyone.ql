import cpp
import semmle.code.cpp.controlflow.SSA
/*
void processString(const char *input) {
    char *buffer = malloc(strlen(input));
    strcpy(buffer, input);
}
*/

class MallocCall extends FunctionCall {
    MallocCall() {
        this.getTarget().hasQualifiedName("malloc")
    }
    Expr getAllocatedSize() {
        if this.getArgument(0) instanceof VariableAccess then
            exists(LocalScopeVariable v, SsaDefinition ssadef |
                this.getArgument(0) = ssadef.getAUse(v) and
                result = ssadef.getAnUltimateDefiningValue(v)
            )
        else
            result = this.getArgument(0)
    }
}

from MallocCall malloc_call
where malloc_call.getAllocatedSize() instanceof StringLiteral
select malloc_call, "malloc off-by-one"