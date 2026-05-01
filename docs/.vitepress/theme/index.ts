import { h, Fragment } from 'vue'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import HeroVisual from './components/HeroVisual.vue'
import HomeFeatureRail from './components/HomeFeatureRail.vue'
import HomeShowcase from './components/HomeShowcase.vue'
import './style.css'

export default {
    extends: DefaultTheme,
    Layout: () => {
        return h(DefaultTheme.Layout, null, {
            'home-hero-image': () => h(HeroVisual),
            'home-features-after': () =>
                h(Fragment, null, [h(HomeFeatureRail), h(HomeShowcase)])
        })
    }
} satisfies Theme
