
/**
* @kind path-problem
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PartialPathGraph // this is different!

class ELInjectionTaintTrackingConfig extends TaintTracking::Configuration {
    ELInjectionTaintTrackingConfig() { this = "ELInjectionTaintTrackingConfig" } // same as before
    override predicate isSource(DataFlow::Node source) // same as before
    {
        exists(Method overriding, Method overridden|
            overriding.overrides(overridden) and 
            overridden.hasName("isValid") and 
            overridden.getDeclaringType().getQualifiedName().matches("javax.validation.ConstraintValidator<%,%>") and
            source.asParameter() = overriding.getParameter(0)
        )
    }
    override predicate isSink(DataFlow::Node sink) // same as before
    {
        exists(Call c|
            c.getArgument(0) = sink.asExpr() and 
            c.getCallee().getQualifiedName().matches("ConstraintValidatorContext.buildConstraintViolationWithTemplate")
        )
    }
    override int explorationLimit() { result =  10} // this is different!
}
from ELInjectionTaintTrackingConfig cfg, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where
  cfg.hasPartialFlow(source, sink, _) and
    exists(Method m|
        m.getQualifiedName() = "SchedulingConstraintSetValidator.isValid" and
        source.getNode().asParameter() = m.getParameter(0)
    )
//   source.getNode() = 
select sink, source, sink, "Partial flow from unsanitized user data"
