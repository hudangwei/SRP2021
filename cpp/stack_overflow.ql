import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

/*
#include <stdio.h>
#include <stdlib.h>

int getnum()
{
	char buf[0x20];
	read(0,buf,0x20);
	return atoi(buf);
}

int main()
{
	unsigned i;
	char buf[0x20];
	char c;
	
	int l;
	l = getnum();
	
	if(l > 0x20){
		return 0;
	}
	
	for(i = 0; i < l; i++){
		c = getchar();
		if (c == '!'){
			break;
		}
		buf[i] = c;
	}
	
	return 0;
}
*/

// from ForStmt for, Expr expr, Expr left, Expr right
// where
//   expr = for.getControllingExpr() and
//   left = expr.(ComparisonOperation).getLeftOperand().getFullyConverted() and
//   right = expr.(ComparisonOperation).getRightOperand().getFullyConverted()
// select expr, left, right

