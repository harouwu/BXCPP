package org.anarres.cpp;

import static org.anarres.cpp.Token.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.CheckForNull;


public class MySegment {
	private List<Unit> seg;
	private List<Token> tokens;
	private List<MySegment> args;
	private Map<String, Macro> macros;
	//private FixList fl;
	/* iterator of the token */
	private int it = 0;
	private int length = 0;
	private int base = 0;
	
	private boolean changed = false;
	private boolean broken = false;
	
	private List<Token> backed;
	
	public void setSeg(List<Unit> seg) {this.seg = seg;}
	public MySegment myclone(){
		MySegment ms = new MySegment(macros, tokens, args);
		/*XXX*/
		ms.seg = this.seg;
		
		return ms;
	}
	
	public MySegment() {
		// TODO Auto-generated constructor stub
		this.seg = new ArrayList<Unit>();
		this.changedBlock = new ArrayList<Unit>();
		this.macros = new HashMap<String, Macro>();
		this.tokens = new ArrayList<Token>();
		this.args = new ArrayList<MySegment>();
		/*we need a structure to record whether any arg has changed*/    	
    	this.argSentinals = new HashMap<Integer, Unit>();
		//this.fl = new FixList();
		this.changed = false;
		this.broken = false;

    	this.backed = new ArrayList<Token>();
	}
	
	public MySegment(List<Token> tokens) {
		this();
		this.tokens = tokens;
	}
	
	public MySegment(Map<String, Macro> macros) {
		this();
		this.macros = macros;
	}
	
	public MySegment(Map<String, Macro> macros, List<Token> tokens) {
		this();
		this.macros = macros;
		this.tokens = tokens;
	}
	
	public MySegment(Map<String, Macro> macros, List<Token> tokens, List<MySegment> args) {
		this(macros, tokens);
		this.args = args;
	}
	
	public List<MySegment> getArgs(){
		return this.args;
	}
	
	public List<Token> getTokens(){
		return this.tokens;
	}
	
	public void setBase(int b) {
		this.base = b;
	}
	
	public int getBase() {
		return this.base;
	}
	
	public int getLength() {
		return this.length;
	}
	
	public void setArgs(List<MySegment> args) {
		this.args = args;
	}
	
	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}
	
	public void addToken(Token tok) {
		this.tokens.add(tok);
	}
	
	public Map<String, Macro> getMacros() {
		return this.macros;
	}
	
	public void setMacros(Map<String, Macro> mac) {
		this.macros = mac;
	}
	
	public void pushUnit(Unit u) {
		this.seg.add(u);
	}
	
	private boolean isWhite(Token tok) {
		if (tok.getType() == Token.WHITESPACE) {
			return true;
		}
		return false;
	}
	
	private Token nextToken() {
		Token token = this.tokens.get(it);
		it++;
		return token;
	}
	
	private void backOneToken() {
		it--;
	}
	
	private Token next_token_nonwhite() {
        Token tok;
        do {
            tok = nextToken();
        } while (isWhite(tok));
        return tok;
    }
	
	/**
     * Returns the named macro.
     *
     * While you can modify the returned object, unexpected things
     * might happen if you do.
     */
    @CheckForNull
    public Macro getMacro(String name) {
        return macros.get(name);
    }
	
	public void mySplit() {
		for (;;) {
			Unit block = new Unit();
			for (;;) {
				if (it == this.tokens.size()) {
					if (it != 0) {
						StringUnits sblock = new StringUnits(block);
	                	sblock.construct();
						this.pushUnit(sblock);
					}
					break;
				}
				boolean macroFlag = false;
				boolean argFlag = false;
				Token tok = this.nextToken();
				switch (tok.getType()) {
				case IDENTIFIER:
	                Macro m = getMacro(tok.getText());
	                if (m == null)
	                    break;
	                Unit blcUnit = macro(m, tok);
	                if (blcUnit == null){
	                    break;
	                }
	                blcUnit.construct();
	                /*Now we have two block*/
	                macroFlag = true;
	                if (block.getOriginal().size() != 0) {
	                	StringUnits sblock = new StringUnits(block);
	                	sblock.construct();
						this.pushUnit(sblock);
					}
	                this.pushUnit(blcUnit);
	                break;
				case M_ARG:
					argFlag = true;
					int idx = ((Integer) tok.getValue()).intValue();
					ArgUnits arg = new ArgUnits(this.args.get(idx));
					arg.addToken(tok);
					if (block.getOriginal().size() != 0) {
	                	StringUnits sblock = new StringUnits(block);
	                	sblock.construct();
						this.pushUnit(sblock);
					}
					arg.construct();
	                this.pushUnit(arg);
					break;
				default:
					break;
				}
				if (macroFlag || argFlag) {
					break;
				}
				block.addToken(tok);
				
			}
			if (it == this.tokens.size()) {
				break;
			}
		}
	}

    /* processes a macro semantic block. */
    private Unit macro(Macro m, Token orig) {
        Token tok;
        Unit blockUnit;
        if(m.isFunctionLike())
        	blockUnit = new FunctionLikeUnits(this.macros, m);
        else
        	blockUnit = new ObjectLikeUnits(this.macros, m);
        
        List<MySegment> args;

        System.out.println("pp: expanding " + m);
        System.out.println("pp: expanding "+ m.getMacroCall());
        
        blockUnit.addToken(orig);
        
        if (m.isFunctionLike()) {
            OPEN:
            for (;;) {
                tok = nextToken();
                 System.out.println("pp: open: token is " + tok);
                switch (tok.getType()) {
                    case WHITESPACE:	/* XXX Really? */

                    case CCOMMENT:
                    case CPPCOMMENT:
                    case NL:
                        break;	/* continue */

                    case '(':
                    	blockUnit.addToken(tok);
                        break OPEN;
                    default:
                        backOneToken();
                        return null;
                }
            }

            // tok = expanded_token_nonwhite();
            tok = next_token_nonwhite();

            /* We either have, or we should have args.
             * This deals elegantly with the case that we have
             * one empty arg. */
            if (tok.getType() != ')' || m.getArgs() > 0) {
                args = new ArrayList<MySegment>();
                MySegment arg = new MySegment(this.macros, new ArrayList<Token>(), this.args); 
                int depth = 0;
                boolean space = false;

                ARGS:
                for (;;) {
                     System.out.println("pp: arg: token is " + tok);
                    switch (tok.getType()) {
                        case EOF:
                            //error(tok, "EOF in macro args");
                        	System.out.println("EOF in macro args, " + tok.toString());
                            return null;

                        case ',':
                            if (depth == 0) {
                                if (m.isVariadic()
                                        && /* We are building the last arg. */ args.size() == m.getArgs() - 1) {
                                	/* XXX do not support variadic Macro now*/
                                    /* Just add the comma. */
                                    arg.addToken(tok);
                                } else {
                                	arg.mySplit();
                                    args.add(arg);
                                    arg = new MySegment(this.macros, new ArrayList<Token>(), this.args); 
                                }
                            } else {
                                arg.addToken(tok);
                            }
                            space = false;
                            break;
                        case ')':
                            if (depth == 0) {
                            	arg.mySplit();
                                args.add(arg);
                                ((FunctionLikeUnits) blockUnit).setArgs(args);
                                blockUnit.addToken(tok);
                                break ARGS;
                            } else {
                                depth--;
                                arg.addToken(tok);
                            }
                            space = false;
                            break;
                        case '(':
                            depth++;
                            arg.addToken(tok);
                            space = false;
                            break;

                        case WHITESPACE:
                        case CCOMMENT:
                        case CPPCOMMENT:
                            /* Avoid duplicating spaces. */
                            space = true;
                            break;

                        default:
                            /* Do not put space on the beginning of
                             * an argument token. */
                        	 /*XXX*/
                            if (space && !arg.tokens.isEmpty())
                                arg.addToken(Token.space);
                            arg.addToken(tok);
                            space = false;
                            break;

                    }
                    // tok = expanded_token();
                    blockUnit.addToken(tok);
                    tok = nextToken();
                }
                /* space may still be true here, thus trailing space
                 * is stripped from arguments. */

                if (args.size() != m.getArgs()) {
                    System.out.println(tok.toString() +
                            "macro " + m.getName()
                            + " has " + m.getArgs() + " parameters "
                            + "but given " + args.size() + " args");
                    /* We could replay the arg tokens, but I
                     * note that GNU cpp does exactly what we do,
                     * i.e. output the macro name and chew the args.
                     */
                    return null;
                }
                /*
                for (Argument a : args) {
                    a.expand(this);
                }
                */

                // System.out.println("Macro " + m + " args " + args);
            } else {
                /* nargs == 0 and we (correctly) got () */
                args = null;
            }
        } else {
            /* Macro without args. */
            args = null;
        }

        return blockUnit;
    }
    
    public void setChanged(boolean b) {this.changed = b;}
	public boolean isChanged() {return this.changed;}
	
	public void setBroken(boolean b) {this.broken = b;}
	public boolean isBroken() {return this.broken;}
    
	public List<Token> getBacked(){return this.backed;}
	public void addTokentoBacked(Token tok){ this.backed.add(tok); }
	
	private List<Unit> changedBlock;
	private Map<Integer, Unit> argSentinals;
	
	public Map<Integer, Unit> getArgSentinals(){return this.argSentinals;}
	
	public void pushChangedBlock(Unit unit) {
		this.changedBlock.add(unit);
	}
	
	public boolean ifTokenListEqual(List<Token> l1, List<Token> l2){
		if (l1.size() != l2.size()) {
			return false;
		}
		for (int i = 0; i < l1.size(); i++) {
			Token tok1 = l1.get(i);
			Token tok2 = l2.get(i);
			if (!tok1.getText().equals(tok2.getText())) {
				return false;
			}
		}
		return true;
	}
	
	public boolean equalsBack(MySegment other) {
		if (this == other) {
			return true;
		}
		if (other == null) {
			return false;
		}
		boolean ifequal = true;
		if (this.changedBlock.size() != other.changedBlock.size()) {
			return false;
		}
		for (int i = 0; i < this.changedBlock.size(); i++) {
			ifequal = ifequal && this.changedBlock.get(i).equalsBack(other.changedBlock.get(i));
		}
		return ifequal;
	}
	
	public List<Unit> getSeg(){
		return this.seg;
	}
	
	public List<Unit> getChangedBlock(){
		return this.changedBlock;
	}
	
	private int[] argChangedFlag; //three status: not specified; changed; not changed;
	
	public void setArgChangedFlag(int[] as){
		this.argChangedFlag = as;
	}
	
	public void setArgSentinals(Map<Integer, Unit> asMap){
		this.argSentinals = asMap;
	}
	
    public MySegment mapback(FixList fl){
    	MySegment cur = new MySegment(this.macros, this.tokens, this.args);
    	//cur.mySplit();
    	argChangedFlag = new int[this.args.size()];
    	for (int i = 0; i < this.seg.size(); i++) {
    		FixList curFixList = fl.subFixListin(this.seg.get(i));
    		Unit unit = this.seg.get(i).mapback(curFixList);
    		if (cur.broken) {
				;
			}
    		else if (unit instanceof ArgUnits) {
    			Token tok = this.seg.get(i).getOriginal().get(0);
				int idx = ((Integer) tok.getValue()).intValue();
    			if (unit.isChanged()) {
					if (argChangedFlag[idx] >= 0) {
						cur.changed = true;
						//if changed or not specified;
						argChangedFlag[idx] = 1;
						//changed
						
						if (this.argSentinals.get(idx) == null) {
							//first occurance of the change
							this.argSentinals.put(idx, unit);
						}
						else {
							//if changed before;
							if (unit.equalsBack(this.argSentinals.get(idx))) {
								;// continue;
							}
							else {
								cur.broken = true;
							}
						}
					}
					else {
						//not changed before
						argChangedFlag[idx] = -1;
						cur.broken = true;
						cur.changed = true;
					}
				}
				else {
					if (argChangedFlag[idx] == 0) {
						argChangedFlag[idx] = -1;
					}
					else{
						cur.broken = true;
						cur.changed = true;
					}
				}
			}
    		else if (unit instanceof FunctionLikeUnits) {
				if (unit.isBroken()) {
					cur.broken = true;
					cur.changed = true;
				}
				else if (unit.isChanged()) {
					Map<Integer, Unit> asMap = unit.getExpanded().getArgSentinals();
					//find if tokens expanded from argUnit in function call go with argUnit's change	
					Unit fu = this.seg.get(i);
					for (int j = 0; j < fu.getExpanded().getArgs().size(); j++) {
						MySegment argSegment = fu.getExpanded().getArgs().get(j);
						if (!asMap.containsKey(j)) {
							//if nothing changed;
							continue;
						}
						Unit changedArg = asMap.get(j);
						MySegment changedSegment = changedArg.getExpanded();
						if (changedSegment.changedBlock.size() != argSegment.seg.size()) {
							System.out.println("WROOOOOOOONNNNNNNNNNGGGGGGG arg");
							cur.changed = true;
							cur.broken = true;
							break;
						}
						for (int k = 0; k < argSegment.seg.size(); k++) {
							Unit unit2 = argSegment.seg.get(k);
							Unit changedUnit = changedSegment.changedBlock.get(k);
							if (unit2 instanceof ArgUnits && changedUnit instanceof ArgUnits) {
								Token tok = unit2.getOriginal().get(0);
								int idx = ((Integer) tok.getValue()).intValue();
								// idx is the current arg index;
								if (changedUnit.isChanged()) {
									if (this.argChangedFlag[idx] >= 0) {
										//changed before;
										this.argChangedFlag[idx] = 1;
										cur.changed = true;
										Unit curChangeUnit = this.argSentinals.get(idx);
										if (curChangeUnit == null) {
											this.argSentinals.put(idx, changedUnit);
										}
										else {
											if (curChangeUnit.equalsBack(changedUnit)) {
												//changed into same thing
												;
											}
											else {
												cur.broken = true;
											}
										}
									}
									else {
										cur.broken = true;
										cur.changed = true;
									}
								}
								else {
									switch (this.argChangedFlag[idx]) {
									case 0:
										this.argChangedFlag[idx] = -1;
										break;
									case -1:
										break;
									default:
										cur.broken = true;
										cur.changed = true;
										break;
									}
								}
							}
							else {
								if (!unit2.equalsBack(changedUnit)) {
									cur.changed = true;
									cur.broken = true;
									j = fu.getExpanded().getArgs().size();
									break;
								}
							}
						}
					}
				}
				else {
					//has not changed;
					List<MySegment> fucArgSegments = this.seg.get(i).getExpanded().getArgs();
					for (int l = 0; l < fucArgSegments.size(); l++) {
						List<Unit> argSeg = fucArgSegments.get(l).getSeg();
						for (int m = 0; m < argSeg.size(); m++) {
							if (argSeg.get(m) instanceof ArgUnits) {
								//if it is an argunit;
								Unit aUnit = argSeg.get(m);
								Token tok = aUnit.getOriginal().get(0);
								int idx = ((Integer) tok.getValue()).intValue();
								if (this.argChangedFlag[idx] > 0) {
									cur.broken = true;
									cur.changed = true;
								}
								else {
									this.argChangedFlag[idx] = -1;
								}
							}
						}
					}
				}
			}
    		else if (unit.isBroken()) {
				cur.broken = true;
				cur.changed = true;
			}
    		else {
				;
			}
    		cur.pushChangedBlock(unit);
    		this.pushChangedBlock(unit);
    		for (int j = 0; j < unit.getExpanded().getBacked().size(); j++) {
				this.addTokentoBacked(unit.getExpanded().getBacked().get(j));
				cur.addTokentoBacked(unit.getExpanded().getBacked().get(j));
			}
		}
    	cur.setArgChangedFlag(this.argChangedFlag);
    	cur.setArgSentinals(this.argSentinals);
    	return cur;
    }
    
    public void setBacked(List<Token> tokens){
    	this.backed = tokens;
    }
    
    public int calcBaseLength(){
    	for (int i = 0; i < this.seg.size(); i++) {
    		seg.get(i).setBase(this.base + this.length);
    		this.length += seg.get(i).calcBaseLength();
		}
    	return this.length;
    }
    
    public void ArgPrintBack(){
    	for (int i = 0; i < this.seg.size(); i++) {
			seg.get(i).PrintBackward();
		}
    }
    
    public void PrintForward(){
    	//System.out.println("Length: " + this.length);
    	//System.out.println("Base: " + this.base);
    	for (int i = 0; i < this.seg.size(); i++) {
			seg.get(i).PrintForward();
		}
    }
    
    public List<Token> tokenListForward(){
    	List<Token> tokens = new ArrayList<Token>();
    	for (int i = 0; i < this.seg.size(); i++) {
			List<Token> temp = seg.get(i).tokenListForward();
			for (int j = 0; j < temp.size(); j++) {
				tokens.add(temp.get(j));
			}
		}
    	return tokens;
    }
	
    public void PrintBackward(){
    	for (int i = 0; i < this.changedBlock.size(); i++) {
			this.changedBlock.get(i).PrintBackward();
		}
    }
}
