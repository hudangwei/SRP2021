import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils

class XPrintfExpr extends FunctionCall {
  XPrintfExpr() {
    this.getTarget().getQualifiedName() in ["printf", "sprintf", "fprintf", "snprintf", "printf_s", "sprintf_s", "snprintf_s"]
  }
  Expr getFormatString() {
    if this.getTarget().getQualifiedName() in ["printf", "printf_s"]
    then result = this.getArgument(0)
    else if this.getTarget().getQualifiedName()  in ["fprintf", "sprintf", "fprintf_s"]
    then result = this.getArgument(1)
    else result = this.getArgument(2)
  }
}

predicate notStringLiteral(XPrintfExpr printf) {
  not printf.getFormatString() instanceof StringLiteral
}

from XPrintfExpr printf
where notStringLiteral(printf)
select printf