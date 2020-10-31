JC = javac
.SUFFIXES: .java .class
.java.class:
		$(JC) $*.java

CLASSES = \
        vencrypt.java \
        vdecrypt.java \
        scrypt.java \
		sbencrypt.java \
        sbdecrypt.java 

default: classes

classes: $(CLASSES:.java=.class)

clean:
		$(RM) *.class