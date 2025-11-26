//16_vectorr.v

module top_module (
    input  [7:0] in,
    output [7:0] out
);
  genvar idx;
  generate
    for (idx = 0; idx < 8; idx = idx + 1) begin : g_for_out
      assign out[idx] = in[7-idx];
    end
  endgenerate

endmodule
