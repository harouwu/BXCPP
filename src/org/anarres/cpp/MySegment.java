package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;

import org.apache.bcel.generic.PUSH;

public class MySegment {
	private List<Unit> seg;
	
	public MySegment() {
		// TODO Auto-generated constructor stub
		this.seg = new ArrayList<Unit>();
	}
	
	public void pushUnit(Unit u) {
		this.seg.add(u);
	}
	
	public void printBlocks(){
		if (seg.size() == 0) {
			return;
		}
		String string = new String("There are " + seg.size() + " blocks");
		System.out.println(string);
		for (int i = 0; i < this.seg.size(); i++) {
			seg.get(i).printOrigin();
		}
		return;
	}
}
