package com.alwanlabs.security.controller;

import com.alwanlabs.security.request.AuthenticationRequest;
import com.alwanlabs.security.request.AuthenticationResponse;
import com.alwanlabs.security.service.CustomUserDetailsService;
import com.alwanlabs.security.service.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;


@RestController
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
            throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        final String token = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @GetMapping("/hellouser")
    public String user(){
        return "Halo user";
    }

    @PostMapping("/test")
    public String testPost(@RequestBody AuthenticationRequest authReq)  {
        return CheckRequestBodyIsNull(authReq);
    }

    private String CheckRequestBodyIsNull(AuthenticationRequest authReq) {
        List<String> requestError = new ArrayList<>();
        try {
            for(PropertyDescriptor propertyDescriptor :
                    Introspector.getBeanInfo(authReq.getClass()).getPropertyDescriptors()){

                Method getter = propertyDescriptor.getReadMethod();
                getter.setAccessible(true);
                Object invoke = getter.invoke(authReq);

                if (invoke == null) {
                    requestError.add(propertyDescriptor.getName());
                }
            }
        } catch (IntrospectionException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
        String join = "Request Body tidak ada. " +String.join(",", requestError);
        return join;
    }
}
