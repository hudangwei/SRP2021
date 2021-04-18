/**
 * @name UAF vulnerbilities checking
 * @kind problem
 * @problem.severity warning
 * @id cpp
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import DataFlow::PathGraph

class Config extends DataFlow::Configuration {
    Config() {
        this = "Config: UAF Vulnerbilities Checking"
    }

    override predicate isSource(DataFlow::Node source) {
        exists(FunctionCall fc |
            fc.getArgument(0) = source.asDefiningArgument() and
            (fc.getTarget().hasGlobalOrStdName("free") or fc.getTarget().hasGlobalOrStdName("delete"))
        )
    }

    override predicate isSink(DataFlow::Node sink) {
        dereferenced(sink.asExpr())
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Memory is $@ and $@, casuing a potential vulnerability.", source, "freed here", sink, "used here"
