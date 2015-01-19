package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.types.Commandline.Argument;

public class StringUnits extends Unit {

	private List<Token> expanded;
	
	public StringUnits() {
		super();
		this.expanded = new ArrayList<Token>();
	}
	
	public StringUnits(Unit u) {
		this();
		super.setOriginal(u.getOriginal());
		super.setBase(u.getBase());
	}

	@Override
	public void construct() {
		// TODO Auto-generated method stub
		System.out.println("Constructing String Unit...");
		this.expanded = super.getOriginal();
		super.length = this.expanded.size();
		return;
		
	}

	@Override
	public void PrintForward() {
		// TODO Auto-generated method stub
		for (int i = 0; i < this.expanded.size(); i++) {
			Token tok = this.expanded.get(i);
			System.out.print(tok.getText());
		}
	}

	@Override
	public void PrintBackward() {
		// TODO Auto-generated method stub
		this.PrintForward();
	}
	
}
