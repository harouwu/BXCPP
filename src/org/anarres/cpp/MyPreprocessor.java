package org.anarres.cpp;

import static org.anarres.cpp.Token.CCOMMENT;
import static org.anarres.cpp.Token.CPPCOMMENT;
import static org.anarres.cpp.Token.EOF;
import static org.anarres.cpp.Token.IDENTIFIER;
import static org.anarres.cpp.Token.NL;
import static org.anarres.cpp.Token.NUMBER;
import static org.anarres.cpp.Token.STRING;
import static org.anarres.cpp.Token.WHITESPACE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class MyPreprocessor {
	
	private MySegment segment; 
	
	private List<Unit> blocks;
	private List<Token> tokens;
	private Map<String, Macro> macros;
	
	private static final Source INTERNAL = new Source() {
        @Override
        public Token token()
                throws IOException,
                LexerException {
            throw new LexerException("Cannot read from " + getName());
        }

        @Override
        public String getPath() {
            return "<internal-data>";
        }

        @Override
        public String getName() {
            return "internal data";
        }
    };
	
	private static final Macro __LINE__ = new Macro(INTERNAL, "__LINE__");
	private static final Macro __FILE__ = new Macro(INTERNAL, "__FILE__");
	private static final Macro __COUNTER__ = new Macro(INTERNAL, "__COUNTER__");
	
	
	
	public MyPreprocessor() {
		super();
		// TODO Auto-generated constructor stub
		this.tokens = new ArrayList<Token>();
		this.blocks = new ArrayList<Unit>();
		this.macros = new HashMap<String, Macro>();
		this.segment = new MySegment();
        macros.put(__LINE__.getName(), __LINE__);
        macros.put(__FILE__.getName(), __FILE__);
        macros.put(__COUNTER__.getName(), __COUNTER__);
	}
	
	public MyPreprocessor(Preprocessor pp) {
		super();
		this.tokens = new ArrayList<Token>();
		this.blocks = new ArrayList<Unit>();
		this.segment = new MySegment();
		try {
			for (;;) {
				Token tok = pp.token();
				if (tok == null)
					break;
				if (tok.getType() == Token.EOF){
					this.tokens.add(tok);
					break;
				}
				 /*
				 if (tok.getType() == Token.WHITESPACE)
					 continue;
				*/
				 tokens.add(tok);
				}
			} catch (Exception e) {
				StringBuilder buf = new StringBuilder("Preprocessor failed:\n");
	            Source s = pp.getSource();
	            while (s != null) {
	                buf.append(" -> ").append(s).append("\n");
	                s = s.getParent();
	            }
	        }
		this.macros = pp.getMacros();
		this.mySplit();
		this.segment.printBlocks();
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
	
	/* iterator of the token */
	private int it = 0;
	
	private void mySplit() {
		for (boolean EOFFlag = false;EOFFlag == false;) {
			Unit block = new Unit();
			block.setType(Unit.NORMAL);
			for (;;) {
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
	                /*Now we have two block*/
	                macroFlag = true;
	                if (block.getOriginal().size() != 0) {
						segment.pushUnit(block);
					}
	                segment.pushUnit(blcUnit);
	                break;

				default:
					break;
				}
				if (macroFlag) {
					break;
				}
				if (tok.getType() == EOF) {
					if (block.getOriginal().size() != 0) {
						segment.pushUnit(block);
					}
					EOFFlag = true;
					break;
				}
				block.addToken(tok);
			}
		}
	}
	
	public void Print() {
		for (int i = 0; i < tokens.size()-1; i++) {
			/* -1 for the last EOF*/
			Token tok = tokens.get(i);
			System.out.print(tok.getText());
		}
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
	
    
	
    /* processes a macro semantic block. */
    private Unit macro(Macro m, Token orig) {
        Token tok;
        Unit blockUnit = new Unit();
        blockUnit.setType(Unit.OBJECT_LIKE_MACRO);
        List<Argument> args;

        System.out.println("pp: expanding " + m);
        System.out.println("pp: expanding "+ m.getMacroCall());
        
        blockUnit.addToken(orig);
        
        if (m.isFunctionLike()) {
            OPEN:
            for (;;) {
            	blockUnit.setType(Unit.FUNCTION_LIKE_MACRO);
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
                args = new ArrayList<Argument>();

                Argument arg = new Argument();
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
                                    args.add(arg);
                                    arg = new Argument();
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
                            if (space && !arg.isEmpty())
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
}
