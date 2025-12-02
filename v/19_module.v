//19_module.v
module top_module ( input a, input b, output out );

    mod_a u_mod_a (
        .in1(a),
        .in2(b),
        .out(out)
    );
    
endmodule

// below part is for only compile, not for HDLBits Site Answers.
module mod_a ( input in1, input in2, output out );

assign out = in1 | in2;

endmodule