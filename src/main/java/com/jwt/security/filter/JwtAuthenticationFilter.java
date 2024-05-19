package com.jwt.security.filter;

import com.jwt.security.service.JwtService;
import com.jwt.security.service.UserDetailsImp;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserDetailsImp userDetailsSrevice;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsImp userDetailsSrevice) {
        this.jwtService = jwtService;
        this.userDetailsSrevice = userDetailsSrevice;
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if(authHeader==null|| !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
       String token = authHeader.substring(7);
        String userName = jwtService.extractUserName(token);

        if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null){
         UserDetails userDetails = userDetailsSrevice.loadUserByUsername(userName);

         if(jwtService.isValid(token,userDetails)){
             UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                     userDetails, null,userDetails.getAuthorities()
             );
             authToken.setDetails(
                     new WebAuthenticationDetailsSource().buildDetails(request)
             );
            SecurityContextHolder.getContext().setAuthentication(authToken);
         }
        }
        filterChain.doFilter(request,response);
    }
}
