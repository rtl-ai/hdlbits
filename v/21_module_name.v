module top_module (
    input a,
    input b,
    input c,
    input d,
    output out1,
    output out2
);
    mod_a u_mod_a (
        .in1(a),
        .in2(b),
        .in3(c),
        .in4(d),
        .out1(out1),
        .out2(out2)
    );
endmodule

// below part is for only compile, not for HDLBits Site Answers.
module mod_a ( output out1, output out2, input in1, input in2, input in3, input in4  );

assign out1 = in1 | ~in2;
assign out2 = in3 | ~in4;

endmodule