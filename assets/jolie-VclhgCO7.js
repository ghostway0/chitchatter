import{g as u}from"./index-BJ3D5hAD.js";function c(e,t){for(var o=0;o<t.length;o++){const r=t[o];if(typeof r!="string"&&!Array.isArray(r)){for(const n in r)if(n!=="default"&&!(n in e)){const i=Object.getOwnPropertyDescriptor(r,n);i&&Object.defineProperty(e,n,i.get?i:{enumerable:!0,get:()=>r[n]})}}}return Object.freeze(Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}))}var s,a;function d(){if(a)return s;a=1,s=e,e.displayName="jolie",e.aliases=[];function e(t){t.languages.jolie=t.languages.extend("clike",{string:{pattern:/(^|[^\\])"(?:\\[\s\S]|[^"\\])*"/,lookbehind:!0,greedy:!0},"class-name":{pattern:/((?:\b(?:as|courier|embed|in|inputPort|outputPort|service)\b|@)[ \t]*)\w+/,lookbehind:!0},keyword:/\b(?:as|cH|comp|concurrent|constants|courier|cset|csets|default|define|else|embed|embedded|execution|exit|extender|for|foreach|forward|from|global|if|import|in|include|init|inputPort|install|instanceof|interface|is_defined|linkIn|linkOut|main|new|nullProcess|outputPort|over|private|provide|public|scope|sequential|service|single|spawn|synchronized|this|throw|throws|type|undef|until|while|with)\b/,function:/\b[a-z_]\w*(?=[ \t]*[@(])/i,number:/(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[+-]?\d+)?l?/i,operator:/-[-=>]?|\+[+=]?|<[<=]?|[>=*!]=?|&&|\|\||[?\/%^@|]/,punctuation:/[()[\]{},;.:]/,builtin:/\b(?:Byte|any|bool|char|double|enum|float|int|length|long|ranges|regex|string|undefined|void)\b/}),t.languages.insertBefore("jolie","keyword",{aggregates:{pattern:/(\bAggregates\s*:\s*)(?:\w+(?:\s+with\s+\w+)?\s*,\s*)*\w+(?:\s+with\s+\w+)?/,lookbehind:!0,inside:{keyword:/\bwith\b/,"class-name":/\w+/,punctuation:/,/}},redirects:{pattern:/(\bRedirects\s*:\s*)(?:\w+\s*=>\s*\w+\s*,\s*)*(?:\w+\s*=>\s*\w+)/,lookbehind:!0,inside:{punctuation:/,/,"class-name":/\w+/,operator:/=>/}},property:{pattern:/\b(?:Aggregates|[Ii]nterfaces|Java|Javascript|Jolie|[Ll]ocation|OneWay|[Pp]rotocol|Redirects|RequestResponse)\b(?=[ \t]*:)/}})}return s}var l=d();const p=u(l),b=c({__proto__:null,default:p},[l]);export{b as j};
//# sourceMappingURL=jolie-VclhgCO7.js.map
