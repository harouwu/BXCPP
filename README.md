<script type="text/x-mathjax-config">
MathJax.Hub.Config({
tex2jax: {inlineMath: [['$','$'], ['\\(','\\)']]}
});
</script>
# BXCPP － Bidirectionalizing C Preprocessor
----------------------------------------------

# How to Install?

To get `BXCPP` project, open your shell and type

	git clone https://github.com/harouwu/BXCPP.git

Use your `eclipse` to import our project from `existing file system`.
		
Run the project, the default input and argument is included.

---------------------------------------------

# How to use?

To change the input file, add filename as arguments in run configuration in `eclipse`.

see more help with `--help`.

	Option                            	Description                           
	------                            -----------                           
	-D, --define <name[=definition]>  	Defines the given macro.              
	-I, --incdir <File: dir>          	Adds the directory dir to the list of 
										directories to be searched for 
										header files.                       
	-U, --undefine <name>             	Undefines the given macro, previously 
                                    	either builtin or defined using -D. 
	-W, --warning <warning>           	Enables the named warning class       
                                    	(trigraphs, import, undef, unused-  
                                    	macros, endif-labels, error).       
	--debug                           	Enables debug output.                 
	--help                            	Displays command-line help.           
	--include <File: file>            	Process file as if "#include "file""  
                                    	appeared as the first line of the   
                                    	primary source file.                
	--iquote <File: dir>              	Adds the directory dir to the list of 
                                    	header files included using "".     
	--version                         	Displays the product version (Version.
                                    	getVersion) and exits.              
	-w, --no-warnings                 	Disables ALL warnings.        

----------------------------------------------

# What is BXCPP?

`BXCPP` is a bidirectional preprocessor for C/CPP language based on an open source project [JCPP](http://www.anarres.org/projects/jcpp/ "Title"). 

It modeles `GCC` forward preprocessing. It accepts general changes given by most programming edit tools. It also makes backward transformation with replacements.

* `BXCPP` is based on a lightweight approach to handling the C preprocessor
  in program-editing tools based bidirectional transformations. We
  analyze different design alternatives and propose five requirements
  for defining the behavior of the backward transformation, including
  GETPUT and PUTGET
  
* We propose an algorithm that meets the five requirements. This
  algorithms is based on an interpretation of CPP as a set of
  rewriting rules, which structurally decomposes the
  bidirectionalization of CPP
  into the bidirectionalizatio of each rule

-------------------------------------------------

# Publication

Find out more detail in our publication [here](http://dev.sei.pku.edu.cn/svn/PLDE/papers/ASE15 "Title").

-------------------------------------------------

# Contributors

Contributors to `BXCPP` implementations are:

* Yiming Wu
* Zhengkai Wu
* Yingfei Xiong

-------------------------------------------------

# Tool References

* [JCPP](http://www.anarres.org/projects/jcpp/ "Title")