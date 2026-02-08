module top_module (
    input  [99:0] in,
    output [99:0] out
);
  genvar i;
  generate
    for (i = 0; i < 100; i = i + 1) begin : g_rev
        assign out[100-1-i] = in[i];
    end
  endgenerate

endmodule
