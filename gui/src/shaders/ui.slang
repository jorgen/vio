// The toolkit's primitive pipeline (gui/PLAN.md, "Rendering"; G26, G39). One instanced quad per
// primitive. A shape is computed analytically per pixel: a rounded rectangle with per-corner radii
// and an optional border, or with blur > 0 a Gaussian-blurred one, which is a shadow. Coverage --
// glyphs and icons -- is read from the atlas texel for texel, one texel per pixel. A segment is a
// line with round ends, by its distance; an area is the region under one, for a filled plot (G41).
//
// The compiled SPIR-V is committed as ui_spirv.h (G25); `cmake --build <dir> --target
// vio_gui_shaders` regenerates it, and needs slangc only then. The interface below -- attribute
// locations, the push constant block and its offsets -- is what src/ui_vulkan.cpp binds, so a change
// here is a change there.

struct Prim
{
    [[vk::location(0)]] float4 rect : RECT;          // x, y, width, height; logical units
    [[vk::location(1)]] float4 radii : RADII;        // top-left, top-right, bottom-right, bottom-left
    [[vk::location(2)]] float4 fill : FILL;          // sRGB, straight alpha
    [[vk::location(3)]] float4 border_color : BORDER;
    [[vk::location(4)]] float2 params : PARAMS;      // border width, blur sigma
    [[vk::location(5)]] uint kind : KIND;            // 0 shape, 1 coverage, 2 segment, 3 area (prim_kind_t)
};

struct Push
{
    float2 origin;      // the run's origin, logical units
    float2 scale;       // framebuffer pixels per logical unit
    float2 target;      // framebuffer size in pixels
    float encode_srgb;  // 1 when the target is UNORM and the shader must encode
    float pad;
};

[[vk::push_constant]] ConstantBuffer<Push> push;
// The glyph atlas: one channel of coverage, read with Load, so no sampler.
[[vk::binding(0, 0)]] Texture2D<float> atlas;

struct Varyings
{
    float4 position : SV_Position;
    nointerpolation float4 box : BOX;        // centre and half size, pixels
    nointerpolation float4 radii : RADII;    // pixels
    nointerpolation float4 fill : FILL;      // linear, premultiplied
    nointerpolation float4 border : BORDER;  // linear, premultiplied
    nointerpolation float2 params : PARAMS;  // border width and blur, pixels
    nointerpolation float4 glyph : GLYPH;    // atlas texel minus pixel (xy); the kind (z)
};

float3 to_linear(float3 c)
{
    return select(c <= 0.04045, c / 12.92, pow((c + 0.055) / 1.055, 2.4));
}

float3 to_srgb(float3 c)
{
    return select(c <= 0.0031308, c * 12.92, 1.055 * pow(c, 1.0 / 2.4) - 0.055);
}

float4 premultiplied_linear(float4 c)
{
    return float4(to_linear(c.rgb) * c.a, c.a);
}

[shader("vertex")]
// SV_VulkanVertexID, not SV_VertexID: Slang makes the latter zero-based by subtracting BaseVertex,
// which needs DrawParameters and so SPIR-V 1.3, and the renderer asks for Vulkan 1.0. Every draw
// starts at vertex 0, so the two are the same number.
Varyings vertexMain(Prim prim, uint vertex : SV_VulkanVertexID)
{
    // Two triangles: 0 1 2, 2 1 3 over the corners (0,0) (1,0) (0,1) (1,1).
    const uint corner_index = vertex < 3 ? vertex : (vertex == 3 ? 2 : (vertex == 4 ? 1 : 3));
    const float2 corner = float2(float(corner_index & 1), float(corner_index >> 1));

    const float2 scale = push.scale;
    Varyings out;
    if (prim.kind == 1)
    {
        // Coverage: the anchor on a whole pixel, the rectangle at its offset from it, one texel per
        // pixel. Rounding the shared anchor rather than each glyph keeps the spacing.
        const float2 anchor = floor((push.origin + prim.rect.xy) * scale + 0.5);
        const float2 top_left = anchor + prim.radii.zw;
        out.position = float4((top_left + corner * prim.rect.zw) / push.target * 2.0 - 1.0, 0.0, 1.0);
        out.box = float4(0.0);
        out.radii = float4(0.0);
        out.fill = premultiplied_linear(prim.fill);
        out.border = float4(0.0);
        out.params = float2(0.0);
        out.glyph = float4(prim.radii.xy - top_left, 1.0, 0.0);
        return out;
    }
    if (prim.kind == 2)
    {
        // A segment: a quad along it, reaching a pixel past its round ends and its sides.
        const float2 a = (push.origin + prim.rect.xy) * scale;
        const float2 b = (push.origin + prim.radii.xy) * scale;
        const float half_width = 0.5 * prim.params.x * scale.x;
        const float2 d = b - a;
        const float len = length(d);
        const float2 along = len > 1e-4 ? d / len : float2(1.0, 0.0);
        const float2 side = float2(-along.y, along.x);
        const float reach = max(half_width, 0.5) + 1.0;
        const float2 pixel = (corner.x < 0.5 ? a - along * reach : b + along * reach) + side * (corner.y < 0.5 ? -reach : reach);
        out.position = float4(pixel / push.target * 2.0 - 1.0, 0.0, 1.0);
        out.box = float4(a, b);
        out.radii = float4(0.0);
        out.fill = premultiplied_linear(prim.fill);
        out.border = float4(0.0);
        out.params = float2(half_width, 0.0);
        out.glyph = float4(0.0, 0.0, 2.0, 0.0);
        return out;
    }
    if (prim.kind == 3)
    {
        // An area: a pixel wider than x0 to x1 on either side, and a pixel above the line's higher
        // end for its antialiased edge. Which pixels are its own the fragment shader decides.
        const float x0 = (push.origin.x + prim.rect.x) * scale.x;
        const float x1 = (push.origin.x + prim.radii.x) * scale.x;
        const float y0 = (push.origin.y + prim.rect.y) * scale.y;
        const float y1 = (push.origin.y + prim.radii.y) * scale.y;
        const float bottom = (push.origin.y + prim.radii.z) * scale.y;
        const float2 pixel = float2(corner.x < 0.5 ? x0 - 1.0 : x1 + 1.0, corner.y < 0.5 ? min(y0, y1) - 1.0 : bottom);
        out.position = float4(pixel / push.target * 2.0 - 1.0, 0.0, 1.0);
        out.box = float4(x0, y0, x1, y1);
        // The ends across as given, in logical units and untouched by arithmetic: what the
        // fragment shader tests a pixel against, so neighbours test against the same number.
        out.radii = float4(bottom, prim.rect.x, prim.radii.x, 0.0);
        out.fill = premultiplied_linear(prim.fill);
        out.border = float4(0.0);
        out.params = float2(0.0);
        out.glyph = float4(0.0, 0.0, 3.0, 0.0);
        return out;
    }
    const float sigma = prim.params.y * scale.x;
    // A pixel of room for the antialiased edge, three sigmas for a shadow's tail.
    const float pad = 1.0 + 3.0 * sigma;
    const float2 low = (push.origin + prim.rect.xy) * scale;
    const float2 size = prim.rect.zw * scale;
    const float2 pixel = low - pad + corner * (size + 2.0 * pad);

    out.position = float4(pixel / push.target * 2.0 - 1.0, 0.0, 1.0);
    const float2 half_size = size * 0.5;
    out.box = float4(low + half_size, half_size);
    out.radii = min(prim.radii * scale.x, min(half_size.x, half_size.y));
    out.fill = premultiplied_linear(prim.fill);
    out.border = premultiplied_linear(prim.border_color);
    out.params = float2(prim.params.x * scale.x, sigma);
    out.glyph = float4(0.0);
    return out;
}

// Signed distance to a rounded box centred on the origin, y down, a radius per corner.
float rounded_box(float2 p, float2 half_size, float4 radii)
{
    const float r = p.x > 0.0 ? (p.y > 0.0 ? radii.z : radii.y) : (p.y > 0.0 ? radii.w : radii.x);
    const float2 q = abs(p) - half_size + r;
    return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - r;
}

float erf_approx(float x)
{
    const float s = sign(x);
    const float a = abs(x);
    float t = 1.0 + (0.278393 + (0.230389 + 0.078108 * (a * a)) * a) * a;
    t *= t;
    return s - s / (t * t);
}

[shader("fragment")]
float4 fragmentMain(Varyings v) : SV_Target
{
    float4 color;
    if (v.glyph.z > 2.5)
    {
        // Under the line from (x0, y0) to (x1, y1), above the bottom. Across, a pixel is this
        // area's when its centre, in the run's logical units, is in [x0, x1): neighbours share that
        // x exactly, and this pixel's x is the same arithmetic in both, so each pixel is drawn by
        // exactly one of them. The rasterizer's own edges cannot promise that -- the driver may
        // fuse the vertex arithmetic differently for two vertices meant to coincide (G41). Along
        // the line the distance is measured square to it, so a steep stretch is as soft as a flat
        // one.
        const float2 p = v.position.xy;
        const float across = p.x / push.scale.x - push.origin.x;
        if (across < v.radii.y || across >= v.radii.z)
            discard;
        const float run = v.box.z - v.box.x;
        const float slope = (v.box.w - v.box.y) / run;
        const float line_y = v.box.y + slope * (p.x - v.box.x);
        const float below = (p.y - line_y) * rsqrt(1.0 + slope * slope);
        color = v.fill * saturate(below + 0.5) * saturate(v.radii.x - p.y + 0.5);
    }
    else if (v.glyph.z > 1.5)
    {
        // Distance to the segment, so the ends are round and consecutive segments join round.
        // Thinner than a pixel, it is drawn a pixel wide and faded by how much thinner.
        const float2 pa = v.position.xy - v.box.xy;
        const float2 ba = v.box.zw - v.box.xy;
        const float h = saturate(dot(pa, ba) / max(dot(ba, ba), 1e-6));
        const float distance = length(pa - ba * h);
        const float half_width = max(v.params.x, 0.5);
        color = v.fill * (saturate(half_width + 0.5 - distance) * (v.params.x / half_width));
    }
    else if (v.glyph.z > 0.5)
    {
        // Coverage blended in linear space (G27).
        const int2 texel = int2(floor(v.position.xy) + v.glyph.xy);
        color = v.fill * atlas.Load(int3(texel, 0));
    }
    else if (v.params.y > 0.0)
    {
        // A shadow: the box's coverage convolved with a Gaussian, approximated through the distance.
        const float d = rounded_box(v.position.xy - v.box.xy, v.box.zw, v.radii);
        color = v.fill * (0.5 - 0.5 * erf_approx(d / (1.41421356 * v.params.y)));
    }
    else
    {
        const float d = rounded_box(v.position.xy - v.box.xy, v.box.zw, v.radii);
        const float outer = saturate(0.5 - d);
        const float inner = v.params.x > 0.0 ? saturate(0.5 - (d + v.params.x)) : 1.0;
        color = lerp(v.border, v.fill, inner) * outer;
    }
    if (push.encode_srgb > 0.5 && color.a > 0.0)
        color.rgb = to_srgb(color.rgb / color.a) * color.a;
    return color;
}
