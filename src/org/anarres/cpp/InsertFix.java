package org.anarres.cpp;

import java.util.List;

public class InsertFix extends Fix {
	
	private int sourceStart;
	private int sourceEnd;
	private InsertUnit insertUnit;
	
	public InsertFix(int pos, int sourceStart){
		super(pos);
		this.sourceStart = sourceStart;
		this.sourceEnd = this.sourceStart;
	}
	
	public InsertFix(int pos, int sourceStart, int sourceEnd) {
		this(pos, sourceStart);
		this.sourceEnd = sourceEnd;
	}
	
	public void construct(MySegment textSegment){
		if (this.sourceEnd < textSegment.getBase() || 
				this.sourceStart >= textSegment.getBase() + textSegment.getLength()) {
			return;
		}
		for (Unit unit : textSegment.getSeg()) {
			MySegment expSegment = unit.getExpanded();
			if (this.sourceStart >= expSegment.getBase() && 
					this.sourceEnd < expSegment.getBase() + expSegment.getLength()) {
				this.construct(expSegment);
				return;
			}
			else if (this.sourceEnd < textSegment.getBase() || 
					this.sourceStart >= textSegment.getBase() + textSegment.getLength()) {
				continue;
			}
			else if (this.sourceStart <= textSegment.getBase() &&
					this.sourceEnd >= textSegment.getBase() + textSegment.getLength() -1) {
				unit = unit.mapback(null);
				this.insertUnit.getExpanded().pushUnit(unit);
				continue;
			}
			else if (this.sourceStart <= textSegment.getBase() ||
					this.sourceEnd >= textSegment.getBase() + textSegment.getLength() -1) {
				List<Token> tokens = unit.tokenListForward();
				StringUnits sunit = new StringUnits();
				for (int i = 0; i < tokens.size(); i++) {
					if (textSegment.getBase() + i >= this.sourceStart &&
						textSegment.getBase() + i <= this.sourceEnd) {
						sunit.addToken(tokens.get(i));
					}
				}
				sunit.construct();
				sunit = (StringUnits)sunit.mapback(null);
				this.insertUnit.getExpanded().pushUnit(sunit);
				continue;
			}
		}
	}
	
	public int getSourceStart(){
		return this.sourceStart;
	}
	
	public int getSourceEnd(){
		return this.sourceEnd;
	}
	
	@Override
	public List<Token> applyFix(List<Token> tl, int base){
		return tl;
	}

}
