// synthesis verilog_input_version verilog_2001
module top_module(
    input a,
    input b,
    input sel_b1,
    input sel_b2,
    output wire out_assign,
    output reg out_always   );

    assign out_assign = ({sel_b1, sel_b2} == 2'b11)
    ? b : a;
    always @(*)
        begin
            casez({sel_b1, sel_b2})
                2'b0?   : out_always = a;
                2'b10   : out_always = a;
                2'b11   : out_always = b;
                default : out_always = 1'b0;
            endcase
        end
endmodule