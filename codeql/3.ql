
/** 
* @kind path-problem 
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class CustomAdditionalStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        //spread taint from
        exists(MethodAccess ma, Callable c |
            // the method access' qualifier
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
                    c.getName() in ["keySet", "stream", "map", "collect"]
                    // PS: removed the below line since now we have a lot of functions that belong to different classes and it isn't necessary to get all their types as the query is fast and retains it accuracy
                    // c.getDeclaringType().getASupertype().getQualifiedName().matches("java.util.Map<%>")
                )
            )
        // or ¯\_(ツ)_/¯
        ) or
        exists(ConstructorCall cc |
            // a constructor call's argument
            node1.asExpr() = cc.getAnArgument() and
            // to the constructor call
            node2.asExpr() = cc and
            // if the type constructed matches
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
            // the isValid we are looking for should be an overriding method 
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

// I wonder what this is ( ͡° ͜ʖ ͡°)

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

// predicate test(MethodAccess ma, VarAccess va) {
//     exists(TryStmt ts, CatchClause cc, Block b|
//         // node1.asExpr() = s and
//         // s.getEnclosingStmt() = ts.getBlock().getAChild() and
//         // node2.asExpr() = ma and
//         // ma.getEnclosingStmt() = ts.getACatchClause().getBlock().getAChild()
//         //ma.getAnArgument() = va.getQualifier()
//         ma.getMethod().getName().matches("a%") and
//         ma.getAnArgument() = va
//     )
// }

// ------------------------------------------------------------------------------------------------
// If you are reading this congrats you found my desperate attempts to understand the TryStmt Class
// ------------------------------------------------------------------------------------------------

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
    if(x.something()) {     // -> if stmt is reported
        y.somtthingElse();  // -> not reported
    }
}
*/  