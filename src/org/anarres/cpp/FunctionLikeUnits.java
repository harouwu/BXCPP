package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class FunctionLikeUnits extends Unit {
	
	private Macro defMacro;
	private MySegment expanded;
	private List<MySegment> args;
	
	public FunctionLikeUnits(Map<String, Macro>macros, Macro mac) {
		super(macros);
		this.defMacro = mac;
		this.expanded = new MySegment(macros, mac.getTokens());
		this.args = new ArrayList<MySegment>();
	}
	
	public void setArgs(List<MySegment> args){
		this.args = args;
		this.expanded.setArgs(args);
	}
	
	@Override
	public void construct(){
		System.out.println("Constructing a Func Macro...");
		/*XXX*/
		this.expanded.mySplit();
	}
	
	@Override
	public void PrintForward(){
		//System.out.print("Printing a Func Macro...");
		this.expanded.PrintForward();
	}
	
	public List<Token> getExpandedTokens() {
		return this.expanded.getExpandedTokens();
	}
}
