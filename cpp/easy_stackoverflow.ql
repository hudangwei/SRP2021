import cpp

predicate existDirectBufferOverflow(LocalVariable lv) {
  // size1: bytes to be written
  // size2: size of array
  exists( FunctionCall fgets, int size1, int size2 |
    lv.getType() instanceof ArrayType and
    fgets.getTarget().getName() = "fgets" and
    fgets.getArgument(0) = lv.getAnAccess() and
    fgets.getArgument(1).getValue().toInt() = size1 and
    lv.getType().(ArrayType).getByteSize() = size2 and
    size1 > size2
  )
  or
  exists( FunctionCall gets |
    gets.getTarget().getName() = "gets" and
    lv.getType() instanceof ArrayType and
    gets.getArgument(0) = lv.getAnAccess()
  )
  or
  exists( FunctionCall read, int size1, int size2 |
    lv.getType() instanceof ArrayType and
    read.getTarget().getName() = "read" and
    read.getArgument(1) = lv.getAnAccess() and
    read.getArgument(2).getValue().toInt() = size1 and
    lv.getType().(ArrayType).getByteSize() = size2 and
    size1 > size2
  )
  or
  exists( FunctionCall strncpy, int size1, int size2 |
    lv.getType() instanceof ArrayType and
    strncpy.getTarget().getName() in ["strncpy", "memcpy"] and 
    strncpy.getArgument(0) = lv.getAnAccess() and
    strncpy.getArgument(2).getValue().toInt() = size1 and
    lv.getType().(ArrayType).getByteSize() = size2 and
    size1 > size2
  )
  or
  exists( FunctionCall strcpy, int size1, int size2, Variable v |
    lv.getType() instanceof ArrayType and
    strcpy.getTarget().getName() = "strcpy" and
    strcpy.getArgument(0) = lv.getAnAccess() and
    size1 = strcpy.getArgument(0).getValue().toInt() and
    size2 = strcpy.getArgument(1).getValue().toInt() and
    size1 > size2
  )
}

from LocalVariable lv
where existDirectBufferOverflow(lv)
select lv