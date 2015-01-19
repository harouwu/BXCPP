package org.anarres.cpp;

import java.util.List;
import java.util.Map;

public class ArgUnits extends Unit {
	private MySegment expanded;
	
	public ArgUnits() {
		super();
		this.expanded = new MySegment();
	}
	
	public ArgUnits(MySegment arg) {
		this();
		this.expanded = arg;
	}
	
	public ArgUnits(MySegment arg, Map<String, Macro> macros) {
		this(arg);
		this.expanded.setMacros(macros);
	}
	
	@Override
	public void construct(){
		/*
		 * do nothing here because the arg has already constructed before. */
		this.expanded.setBase(super.base);
		super.length = this.expanded.getLength();
		return;
	}
	
	@Override
	public void PrintForward(){
		this.expanded.PrintForward();
		return;
	}
	
}
