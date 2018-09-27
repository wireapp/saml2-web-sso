#!/bin/bash

# CPP and (to a lesser extent) QQ are not very well supported by
# brittany, and I can't blame her.  This script therefore (and for
# other potential glitches) allows the user to insert
# `DISABLE_BRITTANY` anywhere in the source modules to keep those
# modules from being processed by brittany (`{-# LANGUAGE CPP #-}` or
# `{-# QuasiQuotes #-}` also do the trick).  To keep the impact small,
# move CPP, multi-line QQ code to their own, small modules.
#
# Further reading:
# - https://github.com/lspitzner/brittany (grep CPP README.md)
# - https://github.com/lspitzner/brittany/issues/90#issuecomment-425126285

SOURCE_PATHS="src test"
GHC_OPTIONS="-XConstraintKinds -XDataKinds -XDefaultSignatures -XDeriveGeneric -XFlexibleContexts -XFlexibleInstances -XGADTs -XInstanceSigs -XKindSignatures -XLambdaCase -XMultiParamTypeClasses -XNoMonomorphismRestriction -XPolyKinds -XRankNTypes -XRecordWildCards -XScopedTypeVariables -XStandaloneDeriving -XTemplateHaskell -XTupleSections -XTypeApplications -XTypeFamilies -XTypeOperators -XTypeSynonymInstances -XViewPatterns"

if [ "`git status -s src/ test/ | grep -v \?\?`" != "" ]; then
    echo "working copy not clean."
    if [ "$1" == "-f" ]; then
        echo "running with -f.  THIS MAY DESTROY YOUR UNCOMMITTED CHANGES."
    else
        echo "run with -f if you want to force changing the uncommitted files."
        echo "WARNING: THIS MAY DESTROY YOUR UNCOMMITTED CHANGES."
        exit 1
    fi
fi

brittany --version | grep -q 0.11 || ( echo "need brittany version 0.11.*"; false )

for i in `git ls-files $SOURCE_PATHS | grep '\.hs'`; do
    echo -n $i
    if grep -q '{-#\s*LANGUAGE CPP\s*#-}' $i; then
        echo "  *** ignored: -XCPP"
    elif grep -q '{-#\s*LANGUAGE QuasiQuotes\s*#-}' $i; then
        echo "  *** ignored: -XQuasiQuotes"
    elif grep -q 'DISABLE_BRITTANY' $i; then
        echo "  *** ignored: file matches /DISABLE_BRITTANY/"
    else
        echo
        brittany --ghc-options="$GHC_OPTIONS" --write-mode=inplace $i || echo -e "*** brittany failed on $i\n"
    fi
done
