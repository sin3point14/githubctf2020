
/**
* @kind path-problem
*/

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources

Variable isSource(DataFlow::Node source) {
  exists(Method overriding, Method overridden, RefType rt,
    Annotation constraintAnnotation, Annotation interfaceAnnotation, 
    AnnotationType interfaceAnnotationType, ParameterizedType pt, 
    Annotatable a, Variable v|
    // the isValid we are looking for should be an overriding method 
    overriding.overrides(overridden) and 
    // the method which is overridden should match the pattern
    overridden.getQualifiedName().matches("ConstraintValidator<%,%>.isValid") and
    // source would be the first parameter of the overriding method
    source.asParameter() = overriding.getParameter(0) and
    // get the RefType of the overriding method's class
    rt = overriding.getDeclaringType() and
    // get all Constraint Annotations 
    constraintAnnotation.toString() = "Constraint" and
    // Check if that annotation is applied on an AnnotationType
    constraintAnnotation = interfaceAnnotationType.getAnAnnotation() and
    // get the type of value passed in "validatedBy" field and it is a ParameterizedType 
    pt = constraintAnnotation.getValue("validatedBy").getAChildExpr().getType() and
    // A sanity check to make sure it is a SomeClass.class equiavlent to Class<SomeClass> 
    pt.getName().matches("Class<%>") and
    // Compare the SomeClass to the RefType of overriding method's class,
    // hence interfaceAnnotationType would by the the AnnotationType to be 
    // validated by the overriding method
    pt.getATypeArgument() = rt and
    // linking AnnotationType to Annotation
    interfaceAnnotation.getType() = interfaceAnnotationType and
    // Check all Annotables for having the interfaceAnnotation
    a.getAnAnnotation() = interfaceAnnotation and
    (
      (
        // if Annotable is a variable 
        v = a
      ) or
      (
        // if Annotable is a type
        v.getType() = a
      ) 
    ) and
    // Variable should be from source
    v.fromSource() and
    // Return all Variables correspoinding to this overriding method
    result = v
  )
}
