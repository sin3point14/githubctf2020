
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

class TryCatchAdditionalStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        exists(TryStmt ts, CatchClause cc, MethodAccess ma1, MethodAccess ma2, VarAccess va, string methodName, RefType caught|
            node1.asExpr() = va and
            va.getEnclosingStmt() = ts.getBlock().getAChild() and
            (ma1.getQualifier() = va or ma1.getAnArgument() = va) and
    
            cc = ts.getACatchClause() and
    
            caught = cc.getACaughtType() and
            
            ma1.getCallee().getAThrownExceptionType().getASupertype*() = caught and
    
            node2.asExpr() = ma2 and
            ma2.getEnclosingStmt() = cc.getBlock().getAChild() and
            ma2.getQualifier() = cc.getVariable().getAnAccess() and
            methodName = ma2.getCallee().getName() and
            ( not (methodName in ["getStackTrace", "getSuppressed"]) ) and
            (methodName.matches("get%") or methodName.matches("Get%") or methodName = "toString")
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


// predicate test2 (DataFlow::Node node1, DataFlow::Node node2) {
//     exists(TryStmt ts, CatchClause cc, MethodAccess ma1, MethodAccess ma2, VarAccess va, string methodName, RefType caught|
//         node1.asExpr() = va and
//         va.getEnclosingStmt() = ts.getBlock().getAChild() and
//         (ma1.getQualifier() = va or ma1.getAnArgument() = va) and

//         cc = ts.getACatchClause() and

//         caught = cc.getACaughtType() and
        
//         ma1.getCallee().getAThrownExceptionType().getASupertype*() = caught and

//         node2.asExpr() = ma2 and
//         ma2.getEnclosingStmt() = cc.getBlock().getAChild() and
//         ma2.getQualifier() = cc.getVariable().getAnAccess() and
//         methodName = ma2.getCallee().getName() and
//         ( not (methodName in ["getStackTrace", "getSuppressed"]) ) and
//         (methodName.matches("get%") or methodName.matches("Get%") or methodName = "toString")
//     )
// }

predicate test(MethodAccess ma, VarAccess va) {
    exists(TryStmt ts, CatchClause cc, Block b|
        // node1.asExpr() = s and
        // s.getEnclosingStmt() = ts.getBlock().getAChild() and
        // node2.asExpr() = ma and
        // ma.getEnclosingStmt() = ts.getACatchClause().getBlock().getAChild()
        //ma.getAnArgument() = va.getQualifier()
        ma.getMethod().getName().matches("a%") and
        ma.getAnArgument() = va
    )
}

/*
getAChild -> returns all try blocks(getBlock) and the catch statements
getAResource -> return all declarations in try(HERE) {...}
getAResourceDecl -> same ^ <---
getAResourceExpr -> none :(   |
getAResourceVariable -> same --
getBasicBlock -> parent block of the try...catch sequence and declaration of varables used in try catch which weren't declared inside
getBlock -> gets the Try block as a Stmt



getEnclosingCallable -> gets parent method or call, if thetry catch is sent as argument
getEnclosingStmt -> very similar to getBasicBlock
*/

/*
getBlock().getAChild() -> gets all the child statement but not blocks that are their childre, eg-
try{
    if(x.something()) {     // -> if stmt is rsported
        y.somtthingElse();  // -> not reported
    }
}
*/  