
/** 
* @kind path-problem 
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class CustomAdditionalStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        exists(MethodAccess ma |    
            node2.asExpr() = ma and
            node1.asExpr() = ma.getQualifier() and
            (ma.getCallee().getQualifiedName() in ["Container.getSoftConstraints", "Container.getHardConstraints"] or
            ma.getCallee().getName() in ["keySet", "stream", "map", "collect"])
        ) or
        exists(ConstructorCall cc |
            node1.asExpr() = cc.getAnArgument() and
            node2.asExpr() = cc and
            cc.getConstructedType().getName().matches("HashSet<%>")
        )
    }
}

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
