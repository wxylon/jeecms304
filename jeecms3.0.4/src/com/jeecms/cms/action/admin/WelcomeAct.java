package com.jeecms.cms.action.admin;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

import com.jeecms.cms.entity.main.CmsSite;
import com.jeecms.cms.entity.main.CmsUser;
import com.jeecms.cms.manager.main.CmsSiteMng;
import com.jeecms.cms.web.AdminContextInterceptor;
import com.jeecms.cms.web.CmsUtils;

@Controller
public class WelcomeAct {
	@RequestMapping("/index.do")
	public String index() {
		return "index";
	}

	@RequestMapping("/top.do")
	public String top(HttpServletRequest request, ModelMap model) {
		// 需要获得站点列表
		List<CmsSite> siteList = cmsSiteMng.getList();
		CmsSite site = CmsUtils.getSite(request);
		CmsUser user = CmsUtils.getUser(request);
		model.addAttribute("siteList", siteList);
		model.addAttribute("site", site);
		model.addAttribute("siteParam", AdminContextInterceptor.SITE_PARAM);
		model.addAttribute("user", user);
		return "top";
	}

	@RequestMapping("/main.do")
	public String main() {
		return "main";
	}

	@RequestMapping("/left.do")
	public String left() {
		return "left";
	}

	@RequestMapping("/right.do")
	public String right() {
		return "right";
	}

	@Autowired
	private CmsSiteMng cmsSiteMng;
}
