
/**
* @kind path-problem
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PartialPathGraph // this is different!

class CustomAdditionalStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        exists(MethodAccess ma, Callable c |
            // spread taint from the method access' qualifier
            node1.asExpr() = ma.getQualifier() and
            // to the method access
            node2.asExpr() = ma and
            c = ma.getCallee() and
            // if
            (
                (
                    // method accessed belongs to these
                    c.getQualifiedName() in ["Container.getSoftConstraints", "Container.getHardConstraints"] 
                // or ¬‿¬
                ) or
                (
                    // it is an access of these methods
                    c.getName() in ["keySet"] and
                    // from a type which inherits from this type
                    c.getDeclaringType().getASupertype().getQualifiedName().matches("java.util.Map<%>")
                )
            )
        )
    }
}

class ELInjectionTaintTrackingConfig extends TaintTracking::Configuration {
    ELInjectionTaintTrackingConfig() { this = "ELInjectionTaintTrackingConfig" } // same as before
    override predicate isSource(DataFlow::Node source) // same as before
    {
        exists(Method overriding, Method overridden|
            // the isValid we are looking for should be an overriding method 
            overriding.overrides(overridden) and 
            // the method which is overridden should match the pattern
            overridden.getQualifiedName().matches("ConstraintValidator<%,%>.isValid") and
            // source would be the first parameter of the overriding method
            source.asParameter() = overriding.getParameter(0)
        )
    }
    override predicate isSink(DataFlow::Node sink) // same as before
    {
        exists(Call c|
            // first argument of the call will be sink
            c.getArgument(0) = sink.asExpr() and 
            // the calls of this function are the ones we're interested in
            c.getCallee().getQualifiedName() = "ConstraintValidatorContext.buildConstraintViolationWithTemplate"
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
