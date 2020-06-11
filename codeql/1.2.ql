
/**
* @kind path-problem
*/

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

predicate isSink(DataFlow::Node sink) {
  exists(Call c|
    // first argument of the call will be sink
    c.getArgument(0) = sink.asExpr() and 
    // the calls of this function are the ones we're interested in
    c.getCallee().getQualifiedName() = "ConstraintValidatorContext.buildConstraintViolationWithTemplate"
  )
}
