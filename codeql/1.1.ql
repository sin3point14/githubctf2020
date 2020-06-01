
/**
* @kind path-problem
*/

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

predicate isSource(DataFlow::Node source) {
  exists(Method overriding, Method overridden|
    overriding.overrides(overridden) and 
    overridden.hasName("isValid") and 
    overridden.getDeclaringType().getQualifiedName().matches("javax.validation.ConstraintValidator<%,%>") and
    source.asParameter() = overriding.getParameter(0)
  )
}

// Call isSource(DataFlow::Node source) { 
//   exists(Call c, Method m |
//     c.getArgument(0) = source.asExpr() |
//     m = c.getCallee() and m.getName() = "isValid"  and result = c
//   )
// }

//rt.hasQualifiedName("javax.validation", "ConstraintValidator") .matches("(ConstraintValidator)")
//and m.getDeclaringType().getASupertype().getName().matches("%ConstraintValidator%")