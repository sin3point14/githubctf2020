
/**
* @kind path-problem
*/

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

predicate isSink(DataFlow::Node sink) {
  exists(Call c|
    c.getArgument(0) = sink.asExpr() and 
    c.getCallee().getQualifiedName().matches("ConstraintValidatorContext.buildConstraintViolationWithTemplate")
  )
}
