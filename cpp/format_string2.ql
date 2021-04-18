import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils

from FunctionCall fc, Expr format, Expr n
where
  fc.getTarget().getName() in ["snprintf", "snprintf_s"] and
  format = fc.getArgument(2) and
  n = fc.getArgument(1).getFullyConverted() and
  upperBound(n) = typeUpperBound(n.getType().getUnspecifiedType())
select fc