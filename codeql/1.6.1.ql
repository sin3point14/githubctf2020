
/** 
* @kind path-problem 
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class CustomAdditionalStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        exists(MethodAccess ma, Callable c |
            // spreead taint from the method access' qualifier
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
                    // the accessed method's name belong in these
                    c.getName() in ["keySet"] and
                    // add the class which declares it inherts from this
                    c.getDeclaringType().getASupertype().getQualifiedName().matches("java.util.Map<%>")
                )
            )
        )
    }
}

class ELInjectionTaintTrackingConfig extends TaintTracking::Configuration {
    ELInjectionTaintTrackingConfig() { this = "ELInjectionTaintTrackingConfig" }
    override predicate isSource(DataFlow::Node source) { 
        exists(Method overriding, Method overridden|
            // the 'isValid' we are looking for should be an overriding method 
            overriding.overrides(overridden) and 
            // the method which is overridden should match the pattern
            overridden.getQualifiedName().matches("ConstraintValidator<%,%>.isValid") and
            // source would be the first parameter of the overriding method
            source.asParameter() = overriding.getParameter(0)
        )
    }
    override predicate isSink(DataFlow::Node sink) { 
        exists(Call c|
            // first argument of the call will be sink
            c.getArgument(0) = sink.asExpr() and 
            // the calls of this function are the ones we're interested in
            c.getCallee().getQualifiedName() = "ConstraintValidatorContext.buildConstraintViolationWithTemplate"
        )
    }
}

from ELInjectionTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
