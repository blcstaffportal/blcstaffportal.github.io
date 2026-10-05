(()=>{
  'use strict';
  const sb=typeof supabaseClient!=='undefined'?supabaseClient:null;
  const register=document.getElementById('principalRegister');
  const claim=document.getElementById('principalClaim');
  const status=document.getElementById('setupStatus');
  if(!sb||!register||!claim)return;
  const message=(text,error=false)=>{
    status.hidden=false;status.textContent=text;status.classList.toggle('error',error);
  };
  const busy=(form,on)=>{const button=form.querySelector('button[type="submit"]');if(button)button.disabled=on};
  const showClaim=()=>{register.hidden=true;claim.hidden=false};
  const validCode=code=>/^[a-f0-9]{64}$/i.test(code);
  const read=form=>{
    const data=new FormData(form);
    return Object.fromEntries([...data.entries()].map(([key,value])=>
      [key,key.includes('password')?String(value):String(value).trim()]));
  };

  register.addEventListener('submit',async event=>{
    event.preventDefault();
    const data=read(register),code=data.code.toLowerCase();
    if(!validCode(code)){message('Enter the full private setup code.',true);return}
    if(data.password!==data.confirm_password||data.password.length<8){
      message('Passwords must match and contain at least 8 characters.',true);return;
    }
    busy(register,true);message('Checking your private setup code…');
    try{
      const check=await sb.rpc('check_principal_setup_code',{p_code:code});
      if(check.error)throw check.error;
      if(!check.data)throw new Error('The setup code is invalid, expired, or already used.');
      const {error}=await sb.auth.signUp({
        email:data.email.toLowerCase(),password:data.password,
        options:{
          emailRedirectTo:location.origin+location.pathname,
          data:{role:'institute_head_setup'}
        }
      });
      if(error)throw error;
      message('Account created. Open the confirmation email on this laptop. After confirming, return here with your private code to complete setup.');
      register.hidden=true;
      // Supabase email confirmation normally creates a session after the link
      // is opened. Never claim the Principal profile before it is verified.
    }catch(error){message(error.message||'Could not start private setup.',true)}
    finally{busy(register,false)}
  });

  claim.addEventListener('submit',async event=>{
    event.preventDefault();
    const data=read(claim);
    if(!validCode(data.code)){message('Enter the full private setup code.',true);return}
    busy(claim,true);message('Verifying your email and completing setup…');
    try{
      const {data:userResult,error:userError}=await sb.auth.getUser();
      if(userError||!userResult?.user)throw new Error('Open the email confirmation link first, then return to this page.');
      const {error}=await sb.rpc('claim_principal_setup',{
        p_code:data.code.toLowerCase(),
        p_first_name:data.first_name,
        p_last_name:data.last_name
      });
      if(error)throw error;
      const signedOut=await sb.auth.signOut({scope:'local'});
      if(signedOut.error)throw new Error('Account created, but this browser session could not be cleared. Close the browser before signing in again.');
      if(location.hash||location.search)history.replaceState({},document.title,location.pathname);
      claim.hidden=true;
      message('Setup complete. Your username is BLC@Principal. Sign in with your password and the email verification code to open your dashboard.');
    }catch(error){message(error.message||'Could not complete private setup.',true)}
    finally{busy(claim,false)}
  });

  (async()=>{
    const {data:{user}}=await sb.auth.getUser();
    if(user)showClaim();
  })();
})();
