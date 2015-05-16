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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class MyPreprocessor {
	
	private MySegment segment; 
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
		this.macros = new HashMap<String, Macro>();
		this.segment = new MySegment();
        macros.put(__LINE__.getName(), __LINE__);
        macros.put(__FILE__.getName(), __FILE__);
        macros.put(__COUNTER__.getName(), __COUNTER__);
	}
	
	public MyPreprocessor(Preprocessor pp) {
		super();
		this.segment = new MySegment();
		try {
			for (;;) {
				Token tok = pp.token();
				if (tok == null)
					break;
				if (tok.getType() == Token.EOF){
					break;
				}
				 /*
				 if (tok.getType() == Token.WHITESPACE)
					 continue;
				*/
				this.segment.addToken(tok);
				}
			} catch (Exception e) {
				StringBuilder buf = new StringBuilder("Preprocessor failed:\n");
	            Source s = pp.getSource();
	            while (s != null) {
	                buf.append(" -> ").append(s).append("\n");
	                s = s.getParent();
	            }
	        }
		
		for (int i = 0; i < this.segment.getTokens().size(); i++) {
			Token tok = this.segment.getTokens().get(i);
			switch (tok.getType()) {
			case ',':
				i++;
				Token nextToken = this.segment.getTokens().get(i);
				if (nextToken.getType() == NL) {
					System.out.println("CommaNewLine, Line: " + nextToken.getLine());
				}
				break;
			default:
				break;
			}
		}
		
		this.macros = pp.getMacros();
		this.segment.setMacros(pp.getMacros());
		this.segment.setBase(0);
		this.segment.mySplit();
		this.segment.calcBaseLength();
		System.out.println("Printing Forward");
		this.segment.PrintForward();
		this.segment.CountMacroCalls();
		System.out.println("Macros Invocations: "+this.segment.getMCC());
		FixList fl1 = new FixList();
		//this.segment.mapback(fl1);
		//this.segment.PrintForward();
		
		//FixList fl = genFixList();
		//fl.printFixes();
		
		/*
		 * test 3
		fl1.addFix(new ChangeFix(11, new Token(Token.IDENTIFIER, "z")));
		fl1.addFix(new ChangeFix(22, new Token(Token.IDENTIFIER, "z")));
		fl1.addFix(new ChangeFix(30, new Token(Token.IDENTIFIER, "z")));
		fl1.addFix(new ChangeFix(43, new Token(Token.IDENTIFIER, "z")));
		*/
		/*
		 * test 4
		for (int i = 29; i <= 71; i++) {
			fl1.addFix(new DeleteFix(i));
		}
		for (int i = 96; i <= 138; i++) {
			fl1.addFix(new DeleteFix(i));
		}
		//fl1.addFix(new DeleteFix(29, 71));
		//fl1.addFix(new DeleteFix(96, 138));//3 16 70 83
		fl1.addFix(new ChangeFix(9, new Token(Token.IDENTIFIER, "y")));
		fl1.addFix(new ChangeFix(22, new Token(Token.IDENTIFIER, "y")));
		fl1.addFix(new ChangeFix(76, new Token(Token.IDENTIFIER, "y")));
		fl1.addFix(new ChangeFix(89, new Token(Token.IDENTIFIER, "y")));
		*/
		/*
		fl1.addFix(new ChangeFix(20, new Token(Token.IDENTIFIER, "z")));
		fl1.addFix(new ChangeFix(22, new Token(Token.IDENTIFIER, "z")));
		fl1.addFix(new ChangeFix(44, new Token(Token.IDENTIFIER, "y")));*/
		
		/*
		fl1.addFix(new ChangeFix(14, new Token(Token.IDENTIFIER, "3")));
		fl1.addFix(new ChangeFix(46, new Token(Token.IDENTIFIER, "3")));
		for (int i = 16; i <= 18; i++) {
			fl1.addFix(new DeleteFix(i));
		}
		for (int i = 50; i <= 52; i++) {
			fl1.addFix(new DeleteFix(i));
		}
		for (int i = 61; i <= 63; i++) {
			fl1.addFix(new DeleteFix(i));
		}
		*/
		fl1=this.genFixList();
		/*
		fl1.addFix(new ChangeFix(5,new Token(Token.IDENTIFIER,"y")));
		fl1.addFix(new ChangeFix(9,new Token(Token.IDENTIFIER,"y")));
		*/
		
		this.segment.mapback(fl1);
		this.segment.CountMacroCallsBack();
		System.out.println("Macros Invocations: "+this.segment.getMCCBack());
		this.segment.PrintBackward();
	}
	
	private FixList genFixList(){
    	FixList fl = new FixList();
    	    	
    	Random random = new Random(456);
    	
    	Iterator<Token> iter=this.segment.tokenListForward().iterator();
    	
    	int changes = 0;
    	
    	for (int i=0;iter.hasNext();++i) {
    		Token now = iter.next();
        		int cur = random.nextInt(10000);
    			//System.out.println(now.getText());
    			//System.out.println(now.getType());
    			if ((now.getType()==IDENTIFIER || now.getType()==NUMBER) && cur<=1000) {
    				int a = random.nextInt(456);
    				Fix f;
    				//System.out.println(now.getText());
    				changes+=1;
    				if (a==0) {
    					f = new DeleteFix(i);
    				} else {
    					int len1 = now.getText().length();
    					char[] s = now.getText().toCharArray();
    					for (int j = 0 ; j < len1 ;++j) {
    						char ch = s[j];
    						if (ch>='a' && ch<='z') {
    							int k=97+random.nextInt(26);
    							ch=(char)k;
    							s[j]=ch;
    						}
    						if (ch>='0' && ch<='9') {
    							int k=48+random.nextInt(10);
    							ch=(char)k;
    							s[j]=ch;
    						}
    						if (ch>='A' && ch<='Z') {
    							int k=65+random.nextInt(26);
    							ch=(char)k;
    							s[j]=ch;
    						}
    					}
    					f = new ChangeFix(i,new Token(Token.IDENTIFIER,s.toString()));
    				}
    				fl.addFix(f);
    			}
    		}
    	
    	System.out.println("Changes: "+changes);
    	
    	/*
    	int[] b = new int[this.segment.getLength()];
    	for (int i = 0; i < 3; i++) {
			Random random = new Random();
			int a = random.nextInt(this.segment.getLength());
			//int a = 7;
			if (b[a] == 32) {
				continue;
			}
			b[a] = 32;
			Fix f;
			if (a % 2 == 0) {
				f = new DeleteFix(a);
			}
			else {
				f = new ChangeFix(a, new Token(Token.IDENTIFIER, "Yiming"));
			}
			fl.addFix(f);
		} */
    	fl.sortFix();
    	return fl;
    }
	
    
	
}
