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
		this.macros = pp.getMacros();
		this.segment.setMacros(pp.getMacros());
		this.segment.setBase(0);
		this.segment.mySplit();
		this.segment.calcBaseLength();
		System.out.println("Printing Forward");
		this.segment.PrintForward();
		
		//FixList fl = genFixList();
		//fl.printFixes();
		
		FixList fl1 = new FixList();
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
		
		this.segment.mapback(fl1);
		this.segment.PrintBackward();
	}
	
	private FixList genFixList(){
    	FixList fl = new FixList();
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
		}
    	fl.sortFix();
    	return fl;
    }
	
    
	
}
