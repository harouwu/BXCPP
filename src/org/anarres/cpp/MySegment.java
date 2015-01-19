package org.anarres.cpp;

import static org.anarres.cpp.Token.CCOMMENT;
import static org.anarres.cpp.Token.CPPCOMMENT;
import static org.anarres.cpp.Token.EOF;
import static org.anarres.cpp.Token.IDENTIFIER;
import static org.anarres.cpp.Token.NL;
import static org.anarres.cpp.Token.WHITESPACE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.CheckForNull;

import org.apache.bcel.generic.PUSH;

public class MySegment {
	private List<Unit> seg;
	private List<Token> tokens;
	private Map<String, Macro> macros;
	/* iterator of the token */
	private int it = 0;
	
	public MySegment() {
		// TODO Auto-generated constructor stub
		this.seg = new ArrayList<Unit>();
		this.macros = new HashMap<String, Macro>();
		this.tokens = new ArrayList<Token>();
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
	
	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}
	
	public void addToken(Token tok) {
		this.tokens.add(tok);
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
				Token tok = this.nextToken();
				switch (tok.getType()) {
				case IDENTIFIER:
	                Macro m = getMacro(tok.getText());
	                if (m == null)
	                    break;
	                Unit blcUnit = macro(m, tok);
	                if (blcUnit == null)
	                    break;
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

				default:
					break;
				}
				if (macroFlag) {
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
                MySegment arg = new MySegment(this.macros); 
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
                                    arg = new MySegment(this.macros);
                                }
                            } else {
                                arg.addToken(tok);
                            }
                            space = false;
                            break;
                        case ')':
                            if (depth == 0) {
                                args.add(arg);
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
    
    public void PrintForward(){
    	for (int i = 0; i < this.seg.size(); i++) {
			seg.get(i).PrintForward();
		}
    }
	
}
