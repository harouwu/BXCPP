package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class FunctionLikeUnits extends Unit {
	
	private Macro defMacro;
	private List<MySegment> args;
	
	public FunctionLikeUnits(Map<String, Macro>macros, Macro mac) {
		super(macros);
		this.defMacro = mac;
		this.expanded = new MySegment(macros, mac.getTokens());
		this.args = new ArrayList<MySegment>();
	}
	
	public FunctionLikeUnits(Map<String, Macro>macros, Macro mac, MySegment seg) {
		this(macros, mac);
		this.expanded = seg;
		this.broken = seg.isBroken();
		this.changed = seg.isChanged();
		this.args = seg.getArgs();
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
	public List<Token> tokenListForward(){
		return this.expanded.tokenListForward();
	}
	
	@Override
	public int calcBaseLength(){
		this.expanded.setBase(this.base);
		return this.length = this.expanded.calcBaseLength();
	}
	
	@Override
	public void PrintBackward(){
		if (!this.changed) {
			for (int i = 0; i < this.original.size(); i++) {
				System.out.print(this.original.get(i).getText());
			}
		}
		else if (this.changed && !this.broken) {
			//SHOULD PRINT THE FUNCTIONAL CALL WITH ARG;
			System.out.print(this.defMacro.getName() + "(");
			
			Map<Integer, Unit> argsentinal = this.expanded.getArgSentinals();
			for (int i = 0; i < this.expanded.getArgs().size(); i++) {
				if (argsentinal.containsKey(i)) {
					argsentinal.get(i).PrintBackward();
				} else {
					this.expanded.getArgs().get(i).PrintBackward();
				}
				if (i != this.expanded.getArgs().size()-1) {
					System.out.print(",");
				}
			}
			System.out.print(")");
		}
		else {
			this.expanded.PrintBackward();
		}
	}
	
	@Override
	public Unit mapback(FixList fl){
		if (fl == null) {
			this.expanded.setBacked(this.original);
			return this;
		}
		
		MySegment segment = this.expanded.mapback(fl);
		FunctionLikeUnits fuUnits = new FunctionLikeUnits(macros, this.defMacro, segment);
		return fuUnits;
	}
	@Override
	public boolean equalsBack(Unit unit){
		if (this == unit)
			return true;
		if (unit == null)
			return false;
		if (getClass() != unit.getClass())
			return false;
		return this.expanded.equalsBack(unit.getExpanded());
	}
	
}
