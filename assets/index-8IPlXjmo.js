import{a as y,b as C,s as R,h as i,r as p,u as h,_ as m,c as d,j as x,d as T,e as g}from"./index-BJ3D5hAD.js";import{T as $}from"./Tablelvl2Context-QduuOR1R.js";function O(e){return y("MuiTableRow",e)}const v=C("MuiTableRow",["root","selected","hover","head","footer"]),_=["className","component","hover","selected"],j=e=>{const{classes:o,selected:a,hover:t,head:l,footer:s}=e;return g({root:["root",a&&"selected",t&&"hover",l&&"head",s&&"footer"]},O,o)},M=R("tr",{name:"MuiTableRow",slot:"Root",overridesResolver:(e,o)=>{const{ownerState:a}=e;return[o.root,a.head&&o.head,a.footer&&o.footer]}})(({theme:e})=>({color:"inherit",display:"table-row",verticalAlign:"middle",outline:0,[`&.${v.hover}:hover`]:{backgroundColor:(e.vars||e).palette.action.hover},[`&.${v.selected}`]:{backgroundColor:e.vars?`rgba(${e.vars.palette.primary.mainChannel} / ${e.vars.palette.action.selectedOpacity})`:i(e.palette.primary.main,e.palette.action.selectedOpacity),"&:hover":{backgroundColor:e.vars?`rgba(${e.vars.palette.primary.mainChannel} / calc(${e.vars.palette.action.selectedOpacity} + ${e.vars.palette.action.hoverOpacity}))`:i(e.palette.primary.main,e.palette.action.selectedOpacity+e.palette.action.hoverOpacity)}}})),u="tr",N=p.forwardRef(function(o,a){const t=h({props:o,name:"MuiTableRow"}),{className:l,component:s=u,hover:n=!1,selected:b=!1}=t,f=m(t,_),r=p.useContext($),c=d({},t,{component:s,hover:n,selected:b,head:r&&r.variant==="head",footer:r&&r.variant==="footer"}),w=j(c);return x.jsx(M,d({as:s,ref:a,className:T(w.root,l),role:s===u?null:"row",ownerState:c},f))});export{N as default,O as getTableRowUtilityClass,v as tableRowClasses};
//# sourceMappingURL=index-8IPlXjmo.js.map
