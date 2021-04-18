/**
  * @name 41_fopen_to_alloca_taint
  * @description Track taint from fopen to alloca.
  * @kind path-problem
  * @problem.severity warning
  */
import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.interfaces.DataFlow
import DataFlow::PathGraph

predicate step1(FunctionCall fc) {
    exists(Expr expr |
        expr = fc.getArgument(0).getFullyConverted() and
        (upperBound(expr) >= 65536 or lowerBound(expr) < 0)
        // (upperBound(expr) < 65536 and lowerBound(expr) >= 0)
    )
}

predicate step2(FunctionCall fc) {
    exists(FunctionCall check, DataFlow::Node source, DataFlow::Node sink, GuardCondition gc |
        check.getTarget().hasQualifiedName(_, "__libc_use_alloca") and
        gc.controls(fc.getBasicBlock(), _) and
        source.asExpr() = check.getBasicBlock().getANode() and
        sink.asExpr() = fc.getAChild*()
    )
}

// Track taint through `__strnlen`.
class StrlenFunction extends DataFlowFunction {
  StrlenFunction() { this.getName().matches("%str%len%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isInParameter(0) and o.isOutReturnValue()
  }
}

// Track taint through `__getdelim`.
class GetDelimFunction extends DataFlowFunction {
  GetDelimFunction() { this.getName().matches("%get%delim%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isInParameter(3) and o.isOutParameterPointer(0)
  }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "fopen_to_alloca_taint" }

    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc |
            fc.getTarget().hasQualifiedName(_, "_IO_new_fopen") and
            source.asExpr() = fc
        )
    }
    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall fc, Expr expr |
            fc.getTarget().hasQualifiedName(_, "__builtin_alloca") and
            expr = fc.getArgument(0).getFullyConverted() and
            sink.asExpr() = expr and
            step1(fc) and
            step2(fc)
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "fopen flows to alloca"