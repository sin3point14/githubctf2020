/** @kind path-problem */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class ELInjectionTaintTrackingConfig extends TaintTracking::Configuration {
    ELInjectionTaintTrackingConfig() { this = "ELInjectionTaintTrackingConfig" }

    override predicate isSource(DataFlow::Node source) { 
        exists(Method overriding, Method overridden|
            overriding.overrides(overridden) and 
            overridden.hasName("isValid") and 
            overridden.getDeclaringType().getQualifiedName().matches("javax.validation.ConstraintValidator<%,%>") and
            source.asParameter() = overriding.getParameter(0)
        )
    }

    override predicate isSink(DataFlow::Node sink) { 
        exists(Call c|
            c.getArgument(0) = sink.asExpr() and 
            c.getCallee().getQualifiedName().matches("ConstraintValidatorContext.buildConstraintViolationWithTemplate")
        )
    }
}

from ELInjectionTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
