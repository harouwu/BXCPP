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
		
		System.out.println("Printing Forward");
		this.segment.PrintForward();
	}

	
    
	
}
