package org.anarres.cpp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class FixList {
	private List<Fix> fixList;
	
	private Comparator<Fix> comparator = new Comparator<Fix>(){
		public int compare(Fix f1, Fix f2){
			return f1.getPos() - f2.getPos();
		}
	};
	
	public FixList() {
		this.fixList = new ArrayList<Fix>();
	}
	
	public List<Fix> getFixList(){
		return this.fixList;
	}
	
	public void addFix(Fix f) {
		this.fixList.add(f);
	}
	
	public void sortFix() {
		Collections.sort(this.fixList, this.comparator);
	}
	
	public void printFixes() {
		for (Fix fix : this.fixList) {
			System.out.println(fix.toString());
		}
	}
	
	public int nextPos() {
		if (this.fixList.size() > 0) {
			Fix f = this.fixList.get(0);
			return f.getPos();
		}
		return -2;
	}
	
	public Fix nextFix() {
		if (this.fixList.size() > 0) {
			Fix f = this.fixList.get(0);
			this.fixList.remove(0);
			return f;
		}
		return null;
	}
	
	public FixList subFixListin(Unit unit){
		FixList fl = new FixList();
		boolean hasFix = false;
		for (int i = 0; i < this.fixList.size(); i++) {
			Fix fix = this.fixList.get(i);
			if (fix.pos >= unit.base && fix.pos < unit.base + unit.length) {
				fl.addFix(fix);
				hasFix = true;
			}
		}
		if (!hasFix) {
			return null;
		}
		return fl;
	}
}
