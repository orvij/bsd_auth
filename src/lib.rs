use std::ffi::CString; 

use bsd_auth_sys as ffi;

pub use ffi::AuthItem;

/// Error type wrapping various error conditions
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Challenge,
    Close,
    Utf8(std::str::Utf8Error),
    Nul(std::ffi::NulError),
    NullSession,
    SetEnv,
    ClrEnv,
    GetItem,
    SetItem,
    SetOption,
    ClrOption,
    ClrOptions,
    SetData,
    UserChallenge,
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Nul(e)
    }
}

/// BSD authentication session
pub struct Session {
    inner: *mut ffi::auth_session_t,
}

impl Session {
    /// Open a new BSD Authentication session with the default service
    /// (which can be changed later).
    pub fn new() -> Self {
        // safety: creates an authentication session,
        // and initializes all members with default values
        //
        // FIXME: check if return value is null?
        // Can be if allocation fails
        Self { inner: unsafe { ffi::auth_open() } }
    }

    /// Create a Session from a raw auth_session_t pointer
    pub fn from_raw(ptr: *mut ffi::auth_session_t) -> Result<Self, Error> {
        if ptr == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            Ok(Self { inner: ptr })
        }
    }

    /// Convert the Session into a raw auth_session_t pointer
    ///
    /// Consumes the Session
    pub fn into_raw(mut self) -> Result<*mut ffi::auth_session_t, Error> {
        let null_ptr = std::ptr::null_mut();
        if self.inner == null_ptr {
            Err(Error::NullSession)
        } else {
            let ret_ptr = self.inner;
            self.inner = null_ptr;
            Ok(ret_ptr)
        }
    }

    /// Request a challenge for the session
    ///
    /// The name and style must have already been specified
    ///
    /// Call is not thread-safe
    pub fn auth_challenge(&self) -> Result<String, Error> {
        // safety: auth_challenge performs null check for the session
        // So, safe to just pass the inner pointer without a check
        let c_res = unsafe { ffi::auth_challenge(self.inner) };
        if c_res == std::ptr::null_mut() {
            Err(Error::Challenge)
        } else {
            // safety: auth_challenge returns challenge C string on success
            //
            // The string should be a valid UTF-8 string pointing to
            // valid memory, so converting to a Rust String should be safe
            let res = unsafe { CString::from_raw(c_res) };
            Ok(res.to_str()?.into())
        }
    }

    /// Close the specified BSD Authentication session
    ///
    /// Frees the inner pointer to the session
    /// future calls with the Session will all return Error
    /// 
    /// Inner pointer can be reset with calls that open a new session
    ///
    /// Call is not thread-safe
    pub fn auth_close(&self) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            return Err(Error::NullSession);
        }
        let res = unsafe { ffi::auth_close(self.inner) };
        if res == 0 {
            Err(Error::Close)
        } else {
            Ok(())
        }
    }

    /// Get the BSD Authentication session state
    /// (0 = unauth, 1 = auth)
    ///
    /// Call is not thread-safe
    pub fn auth_getstate(&self) -> Result<i32, Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            Ok(unsafe { ffi::auth_getstate(self.inner) })
        }
    }

    /// Set/unset the requested environment variables.
    /// Mark the variables as set so they will not be set a second time.
    ///
    /// Environment variables are requested via the spool
    /// of the auth_session_t struct
    ///
    /// Call is not thread-safe
    pub fn auth_setenv(&self) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            // safety: auth_setenv does not check the validity of the spool
            // There is no way to check for an error
            //
            // auth_session_t is an opaque type, so we can't check either
            unsafe { ffi::auth_setenv(self.inner) };
            Ok(())
        }
    }

    /// Clear out any of the requested environment variables.
    ///
    /// Call is not thread-safe
    pub fn auth_clrenv(&self) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            // safety: auth_setenv does not check the validity of the spool
            // There is no way to check for an error
            //
            // auth_session_t is an opaque type, so we can't check either
            unsafe { ffi::auth_clrenv(self.inner) };
            Ok(())
        }
    }

    /// Get the item value
    ///
    /// Call is not thread-safe
    pub fn auth_getitem(&self, item: AuthItem) -> Result<String, Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            // safety: auth_getitem also checks for null, so the call is safe
            let c_res = unsafe { ffi::auth_getitem(self.inner, item as u32) };
            if c_res == std::ptr::null_mut() {
                // return error if the value is unset
                Err(Error::GetItem)
            } else {
                // safety: at this point, the value returned should be a
                // pointer to a valid UTF-8 C string
                let c_res = unsafe { CString::from_raw(c_res) };
                let res = c_res.to_str()?.into();
                let _ = c_res.into_raw();
                Ok(res)
            }
        }
    }

    /// Set an item value
    ///
    /// Value must be a valid UTF-8 string
    ///
    /// Call is not thread-safe
    pub fn auth_setitem(&self, item: AuthItem, value: &str) -> Result<(), Error> {
        let c_str = CString::new(value)?;
        // safety: auth_setitem checks for null, and sets errno to EINVAL
        // if the auth_session_t* or members are null (so let it do the checks).
        let c_res = match item {
            AuthItem::All => unsafe {
                // pass null to clear all member items, non-null errors
                ffi::auth_setitem(self.inner, item as u32, std::ptr::null_mut())
            }
            AuthItem::Interactive => unsafe {
                let ptr = if value.len() == 0 {
                    // set to null to unset the interactive flag
                    std::ptr::null_mut()
                } else {
                    // set to non-null to set the interactive flag
                    c_str.into_raw()
                };
                ffi::auth_setitem(self.inner, item as u32, ptr)
            }
            _ => unsafe {
                ffi::auth_setitem(self.inner, item as u32, c_str.into_raw())
            }
        };
            
        if c_res == -1 {
            Err(Error::SetItem)
        } else {
            Ok(())
        }
    }

    /// Set an option name and value
    ///
    /// Returns error if:
    ///
    /// - session is null
    /// - option allocation fails
    /// - name is too long
    ///
    /// Call is not thread-safe
    pub fn auth_setoption(&self, name: &str, value: &str) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            let n = CString::new(name)?;
            let v = CString::new(value)?;
            // safety: auth_setoption checks for null arguments, and argument validity
            let c_res = unsafe { ffi::auth_setoption(self.inner, n.into_raw(), v.into_raw()) };

            if c_res == -1 {
                Err(Error::SetOption)
            } else {
                Ok(())
            }
        }
    }

    /// Clear all set options in the BSD Authentication session
    ///
    /// Call is not thread-safe
    pub fn auth_clroptions(&self) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            // safety: auth_clroptions checks for null
            // in the optlist member, call is safe with the call above
            unsafe { ffi::auth_clroptions(self.inner) };
            Ok(())
        }
    }

    /// Clear the option matching the specified name
    ///
    /// Call is not thread-safe
    pub fn auth_clroption(&self, option: &str) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            let opt = CString::new(option)?;
            // safety: auth_clroption checks for null
            // in the optlist member, call is safe with the call above
            unsafe { ffi::auth_clroption(self.inner, opt.into_raw()) };
            Ok(())
        }
    }

    /// Set BSD Authentication session data to be read into the spool.
    ///
    /// Data is not mutated, but needs to be a mutable reference
    /// to satisfy the borrow checker.
    ///
    /// Call is not thread-safe
    pub fn auth_setdata(&self, data: &mut [u8]) -> Result<(), Error> {
        if self.inner == std::ptr::null_mut() {
            Err(Error::NullSession)
        } else {
            let d = data.as_mut_ptr() as *mut _;
            let len = data.len() as u64;
            // safety: auth_setdata checks for nulls of members. With the null
            // check for the session above, the call is safe.
            let c_res = unsafe { ffi::auth_setdata(self.inner, d, len) };

            if c_res == -1 {
                Err(Error::SetData)
            } else {
                Ok(())
            }
        }
    }

    /// From `man 3 auth_approval`:
    ///
    /// The auth_usercheck() function operates the same as the auth_userokay()
    /// function except that it does not close the BSD Authentication session
    /// created.  Rather than returning the status of the session, it returns a
    /// pointer to the newly created BSD Authentication session.
    ///
    /// If authentication fails, a null pointer is returned, which results in
    /// an error in the Rust API.
    ///
    /// For more details see `man 3 auth_approval`
    pub fn auth_usercheck(
        name: &str,
        style: Option<&str>,
        auth_type: Option<&str>,
        password: Option<&mut str>,
    ) -> Result<Self, Error> {
        let c_name = CString::new(name)?;
    
        let style_ptr = match style {
            Some(s) => CString::new(s)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let type_ptr = match auth_type {
            Some(t) => CString::new(t)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let passwd_ptr = match password {
            Some(p) => {
                let ptr = CString::new(&*p)?.into_raw();
                // safety: password guaranteed non-null, and points to valid
                // memory
                unsafe { libc::explicit_bzero(p.as_mut_ptr() as *mut _, p.len()) };
                ptr
            }
            None => std::ptr::null_mut(),
        };
    
        // safety: auth_usercheck performs null checks on all the arguments
        //
        // If the user name is invalid, or authentication fails, a null pointer
        // is returned
        let ses_ptr = unsafe { ffi::auth_usercheck(c_name.into_raw(), style_ptr, type_ptr, passwd_ptr) };
    
        Self::from_raw(ses_ptr)
    }
    
    ///  From `man 3 auth_approval`:
    ///
    ///  Provides a single function call interface.
    ///
    ///  Provided with a user's name in name, and an optional style, type, and password, the auth_userokay() function returns a simple yes/no response.
    ///
    ///  A return value of true implies failure; a false return value implies success.
    ///  Other error conditions result in Error.
    ///
    ///  If style is not NULL, it specifies the desired style of authentication to be used.
    ///  If it is NULL then the default style for the user is used.
    ///  In this case, name may include the desired style by appending it to the user's name with a single colon (`:') as a separator.
    ///  If type is not NULL then it is used as the authentication type (such as "auth-myservice").
    ///  If password is NULL then auth_userokay() operates in an interactive mode with the user on standard input, output, and error.
    ///  If password is specified, auth_userokay() operates in a non-interactive mode and only tests the specified passwords.
    ///  This non-interactive method does not work with challenge-response authentication styles.
    ///
    ///  For security reasons, when a password is specified, auth_userokay() will zero out its value before it returns. 
    ///
    /// For more details see `man 3 auth_approval`
    pub fn auth_userokay(
        name: &str,
        style: Option<&str>,
        auth_type: Option<&str>,
        password: Option<&mut str>,
    ) -> Result<bool, Error> {
        let c_name = CString::new(name)?;
    
        let style_ptr = match style {
            Some(s) => CString::new(s)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let type_ptr = match auth_type {
            Some(t) => CString::new(t)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let passwd_ptr = match password {
            Some(p) => {
                let ptr = CString::new(&*p)?.into_raw();
                // safety: password guaranteed non-null, and points to valid
                // memory
                unsafe { libc::explicit_bzero(p.as_mut_ptr() as *mut _, p.len()) };
                ptr
            }
            None => std::ptr::null_mut(),
        };
    
        // safety: auth_userokay performs null checks on all the arguments
        //
        // If the user name is invalid, or authentication fails, a null pointer
        // is returned
        let ret = unsafe { ffi::auth_userokay(c_name.into_raw(), style_ptr, type_ptr, passwd_ptr) };
    
        Ok(ret != 0)
    }
    
    /// Get an authentication challenge for the user, with optional style and type
    ///
    /// IMPORTANT:
    ///
    /// The FFI call returns a session pointer, which is owned by the C library.
    /// The caller must release ownership of the pointer to prevent a double-free
    /// Example:
    ///
    /// ```rust,no_build
    /// # use bsd_auth::Session;
    /// /* Create the session and get the challenge */
    /// let (session, _chal) = Session::auth_userchallenge("nobody", Some("passwd"), Some("auth_doas")).unwrap();
    ///
    /// /* Prompt the user for a response */
    /// let mut response = String::from_utf8([1; 1024].to_vec()).unwrap();
    /// session.auth_userresponse(&mut response, 0).unwrap();
    ///
    /// /* Release ownership of the inner pointer */
    /// let _ = session.into_raw();
    /// ```
    ///
    /// From `man 3 auth_approval`:
    ///
    /// The auth_userchallenge() function takes the same name, style, and type arguments as does auth_userokay().
    ///
    /// However, rather than authenticating the user, it returns a possible challenge in the pointer pointed to by challengep.
    ///
    /// To provide a safe Rust API the challenge pointer is converted to a string.
    ///
    /// The memory pointed to by challengep is cleared for security.
    ///
    /// The return value of the function is a pointer to a newly created BSD Authentication session.
    ///
    /// This challenge, if not NULL, should be displayed to the user.
    ///
    /// In any case, the user should provide a password which is the response in a call to auth_userresponse().
    ///
    /// For more information, see `man 3 auth_approval`
    pub fn auth_userchallenge(
        name: &str,
        style: Option<&str>,
        auth_type: Option<&str>,
    ) -> Result<(Self, String), Error> {
        let name_ptr = CString::new(name)?.into_raw();
    
        let style_ptr = match style {
            Some(s) => CString::new(s)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let type_ptr = match auth_type {
            Some(t) => CString::new(t)?.into_raw(),
            None => std::ptr::null_mut(),
        };
    
        let mut challenge_ptr = CString::new("")?.into_raw();
    
        // safety: auth_userchallenge performs null checks on all of the
        // arguments. If the user name is invalid, or authentication fails,
        // a null pointer is returned
        let ses_ptr = unsafe { ffi::auth_userchallenge(name_ptr, style_ptr, type_ptr, &mut challenge_ptr) };
    
        let challenge = if challenge_ptr == std::ptr::null_mut() {
           format!("doas passphrase for {}: ", name) 
        } else {
            // safety: with the null check above, the challenge pointer should
            // point to a valid C string
            unsafe {
                let cstr = CString::from_raw(challenge_ptr);
                let c = cstr.to_str()?.to_string();
                // release ownership of challenge pointer
                // to let auth_userchallenge handle the memory
                let _ = cstr.into_raw();
                c
            }
        };

        Ok((Self::from_raw(ses_ptr)?, challenge))
    }
    
    /// From `man 3 auth_approval`:
    ///
    /// In addition to the password, the pointer returned by auth_userchallenge()
    /// should be passed in as as and the value of more should be non-zero if the
    /// program wishes to allow more attempts.
    ///
    /// If more is zero then the session will be closed.
    ///
    /// The auth_userresponse() function closes the BSD Authentication session and has the same return value as auth_userokay().
    ///
    /// For security reasons, when a response is specified, auth_userresponse() will zero out its value before it returns.
    pub fn auth_userresponse(
        &self,
        response: &mut str,
        more: i32,
    ) -> Result<bool, Error> {
        let res_ptr = CString::new(&*response)?.into_raw();

        // safety: auth_userresponse checks arguments for null, and clears the
        // memory pointed to by the response pointer
        let res = unsafe { ffi::auth_userresponse(self.inner, res_ptr, more) };

        Ok(res != 0)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.inner != std::ptr::null_mut() {
            // safety: auth_clean performs null checks
            // on inner members before freeing
            unsafe { ffi::auth_close(self.inner); } 
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session() {
        let _session = Session::new();
    }

    #[test]
    fn test_usercheck() {
        let name = "nobody".to_string();
        let mut passwd = "some_password".to_string();
        {
            let session = Session::auth_usercheck(name.as_str(), None, None, Some(&mut passwd.clone())).unwrap();
            assert_eq!(session.auth_getitem(AuthItem::Name).unwrap(), name);
        }
        {
            let session = Session::auth_usercheck(name.as_str(), Some("passwd"), None, Some(&mut passwd.clone())).unwrap();
            assert_eq!(session.auth_getitem(AuthItem::Name).unwrap(), name);
        }
        {
            let session = Session::auth_usercheck(name.as_str(), Some("passwd"), Some("type"), Some(&mut passwd.clone())).unwrap();
            assert_eq!(session.auth_getitem(AuthItem::Name).unwrap(), name);
        }
        {
            let session = Session::auth_usercheck(name.as_str(), Some("passwd"), None, Some(&mut passwd)).unwrap();
            assert_eq!(session.auth_getitem(AuthItem::Name).unwrap(), name);
        }
    }
}
