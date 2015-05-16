package org.anarres.cpp;

public class InsertUnit extends Unit {
	
	public InsertUnit(MySegment seg){
		super();
		this.expanded = new MySegment(seg.getMacros(), seg.getTokens(), seg.getArgs());
	}
	
	@Override
	public void construct(){
		//useless fuction;
		return;
	}
	
	@Override
	public void PrintForward(){
		//useless fuction;
		return;
	}
	
	@Override
	public void PrintBackward(){
		if (!this.changed) {
			for (int i = 0; i < this.original.size(); i++) {
				//System.out.print(this.original.get(i).getText());
				this.expanded.ArgPrintBack();
			}
		}
		else {
			this.expanded.PrintBackward();
		}
	}
	
}
