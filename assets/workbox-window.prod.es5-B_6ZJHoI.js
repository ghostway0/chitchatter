try{self["workbox:window:7.0.0"]&&_()}catch{}function S(t,o){return new Promise(function(e){var i=new MessageChannel;i.port1.onmessage=function(f){e(f.data)},t.postMessage(o,[i.port2])})}function W(t,o){for(var e=0;e<o.length;e++){var i=o[e];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(t,i.key,i)}}function E(t,o){(o==null||o>t.length)&&(o=t.length);for(var e=0,i=new Array(o);e<o;e++)i[e]=t[e];return i}function k(t,o){var e;if(typeof Symbol>"u"||t[Symbol.iterator]==null){if(Array.isArray(t)||(e=function(f,d){if(f){if(typeof f=="string")return E(f,d);var h=Object.prototype.toString.call(f).slice(8,-1);return h==="Object"&&f.constructor&&(h=f.constructor.name),h==="Map"||h==="Set"?Array.from(f):h==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(h)?E(f,d):void 0}}(t))||o){e&&(t=e);var i=0;return function(){return i>=t.length?{done:!0}:{done:!1,value:t[i++]}}}throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}return(e=t[Symbol.iterator]()).next.bind(e)}try{self["workbox:core:7.0.0"]&&_()}catch{}var y=function(){var t=this;this.promise=new Promise(function(o,e){t.resolve=o,t.reject=e})};function b(t,o){var e=location.href;return new URL(t,e).href===new URL(o,e).href}var g=function(t,o){this.type=t,Object.assign(this,o)};function p(t,o,e){return e?o?o(t):t:(t&&t.then||(t=Promise.resolve(t)),o?t.then(o):t)}function L(){}var j={type:"SKIP_WAITING"};function P(t,o){return t&&t.then?t.then(L):Promise.resolve()}var x=function(t){var o,e;function i(v,c){var n,r;return c===void 0&&(c={}),(n=t.call(this)||this).nn={},n.tn=0,n.rn=new y,n.en=new y,n.on=new y,n.un=0,n.an=new Set,n.cn=function(){var s=n.fn,a=s.installing;n.tn>0||!b(a.scriptURL,n.sn.toString())||performance.now()>n.un+6e4?(n.vn=a,s.removeEventListener("updatefound",n.cn)):(n.hn=a,n.an.add(a),n.rn.resolve(a)),++n.tn,a.addEventListener("statechange",n.ln)},n.ln=function(s){var a=n.fn,u=s.target,l=u.state,m=u===n.vn,w={sw:u,isExternal:m,originalEvent:s};!m&&n.mn&&(w.isUpdate=!0),n.dispatchEvent(new g(l,w)),l==="installed"?n.wn=self.setTimeout(function(){l==="installed"&&a.waiting===u&&n.dispatchEvent(new g("waiting",w))},200):l==="activating"&&(clearTimeout(n.wn),m||n.en.resolve(u))},n.dn=function(s){var a=n.hn,u=a!==navigator.serviceWorker.controller;n.dispatchEvent(new g("controlling",{isExternal:u,originalEvent:s,sw:a,isUpdate:n.mn})),u||n.on.resolve(a)},n.gn=(r=function(s){var a=s.data,u=s.ports,l=s.source;return p(n.getSW(),function(){n.an.has(l)&&n.dispatchEvent(new g("message",{data:a,originalEvent:s,ports:u,sw:l}))})},function(){for(var s=[],a=0;a<arguments.length;a++)s[a]=arguments[a];try{return Promise.resolve(r.apply(this,s))}catch(u){return Promise.reject(u)}}),n.sn=v,n.nn=c,navigator.serviceWorker.addEventListener("message",n.gn),n}e=t,(o=i).prototype=Object.create(e.prototype),o.prototype.constructor=o,o.__proto__=e;var f,d,h=i.prototype;return h.register=function(v){var c=(v===void 0?{}:v).immediate,n=c!==void 0&&c;try{var r=this;return function(s,a){var u=s();return u&&u.then?u.then(a):a(u)}(function(){if(!n&&document.readyState!=="complete")return P(new Promise(function(s){return window.addEventListener("load",s)}))},function(){return r.mn=!!navigator.serviceWorker.controller,r.yn=r.pn(),p(r.bn(),function(s){r.fn=s,r.yn&&(r.hn=r.yn,r.en.resolve(r.yn),r.on.resolve(r.yn),r.yn.addEventListener("statechange",r.ln,{once:!0}));var a=r.fn.waiting;return a&&b(a.scriptURL,r.sn.toString())&&(r.hn=a,Promise.resolve().then(function(){r.dispatchEvent(new g("waiting",{sw:a,wasWaitingBeforeRegister:!0}))}).then(function(){})),r.hn&&(r.rn.resolve(r.hn),r.an.add(r.hn)),r.fn.addEventListener("updatefound",r.cn),navigator.serviceWorker.addEventListener("controllerchange",r.dn),r.fn})})}catch(s){return Promise.reject(s)}},h.update=function(){try{return this.fn?P(this.fn.update()):void 0}catch(v){return Promise.reject(v)}},h.getSW=function(){return this.hn!==void 0?Promise.resolve(this.hn):this.rn.promise},h.messageSW=function(v){try{return p(this.getSW(),function(c){return S(c,v)})}catch(c){return Promise.reject(c)}},h.messageSkipWaiting=function(){this.fn&&this.fn.waiting&&S(this.fn.waiting,j)},h.pn=function(){var v=navigator.serviceWorker.controller;return v&&b(v.scriptURL,this.sn.toString())?v:void 0},h.bn=function(){try{var v=this;return function(c,n){try{var r=c()}catch(s){return n(s)}return r&&r.then?r.then(void 0,n):r}(function(){return p(navigator.serviceWorker.register(v.sn,v.nn),function(c){return v.un=performance.now(),c})},function(c){throw c})}catch(c){return Promise.reject(c)}},f=i,(d=[{key:"active",get:function(){return this.en.promise}},{key:"controlling",get:function(){return this.on.promise}}])&&W(f.prototype,d),i}(function(){function t(){this.Pn=new Map}var o=t.prototype;return o.addEventListener=function(e,i){this.Sn(e).add(i)},o.removeEventListener=function(e,i){this.Sn(e).delete(i)},o.dispatchEvent=function(e){e.target=this;for(var i,f=k(this.Sn(e.type));!(i=f()).done;)(0,i.value)(e)},o.Sn=function(e){return this.Pn.has(e)||this.Pn.set(e,new Set),this.Pn.get(e)},t}());export{x as Workbox,g as WorkboxEvent,S as messageSW};
//# sourceMappingURL=workbox-window.prod.es5-B_6ZJHoI.js.map
