import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

class Config extends TaintTracking::Configuration {
  Config() {
    this = "Config"
  }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(FunctionCall).getTarget().getName() = "get_user_input_str"
  }

  override predicate isSink(DataFlow::Node sink) {
    exists( FunctionCall system |
      system.getTarget().getName() = "system" and
      sink.asExpr() = system.getArgument(0)
    )
  }
  override predicate isSanitizer(DataFlow::Node nd) {
    exists( FunctionCall fc |
      fc.getTarget().getName() = "clean_data" and
      globalValueNumber(fc.getArgument(0)) = globalValueNumber(nd.asExpr())
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Config cfg
where cfg.hasFlowPath(source, sink)
select source, sink

// fc.getEnclosingFunction() returns its parent function
