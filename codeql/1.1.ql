
/**
* @kind path-problem
*/

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

predicate isSource(DataFlow::Node source) {
  exists(Method overriding, Method overridden|
    // the isValid we are looking for should be an overriding method 
    overriding.overrides(overridden) and 
    // the method which is overridden should match the pattern
    overridden.getQualifiedName().matches("ConstraintValidator<%,%>.isValid") and
    // source would be the first parameter of the overriding method
    source.asParameter() = overriding.getParameter(0)
  )
}

// OwO what's this?
// Call isSource(DataFlow::Node source) { 
//   exists(Call c, Method m |
//     c.getArgument(0) = source.asExpr() |
//     m = c.getCallee() and m.getName() = "isValid"  and result = c
//   )
// }

//rt.hasQualifiedName("javax.validation", "ConstraintValidator") .matches("(ConstraintValidator)")
//and m.getDeclaringType().getASupertype().getName().matches("%ConstraintValidator%")